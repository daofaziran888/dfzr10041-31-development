"""按事件发生时间分窗的异常告警与转发引擎。

现有采集链路里的异常检测只看"本次传入的记录总数"，无法表达"某个时间窗内
至少 N 条错误才触发"，也没有幂等的转发台账。本模块补上三件事：

1. **窗口**：事件按 ``event_time``（发生时间）落进固定长度的时间窗，晚到的
   事件仍回到它发生的那一窗，不会因为到达晚而落进当前窗口。
2. **告警批次**：每个 ``(事件类型, 时间窗, 阈值, 目标)`` 只产生一条告警，
   只有达到门槛的窗口才会生成可转发的包；重传同一原始行不会增加计数。
3. **送达与更正台账**：转发包发出后分"目标实际收到"和"本端登记送达"两步；
   已送达的告警如果因为原行更正不再达门槛，向同一目标补发一条能关联原告警
   的更正包，同一更正只交付一次。原告警与更正分别核销，未交付的窗口继续
   参与下一轮派发。

模块只依赖标准库，所有时间比较都在内存里完成，便于测试与确定性重放。
"""
from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

# ---------- 状态常量 ----------

ALERT_PENDING = "待派发"
ALERT_SENT = "已发送待确认"
ALERT_DELIVERED = "已送达"
ALERT_WITHDRAWN = "已撤回"

DELIVERY_PENDING = "待派发"
DELIVERY_SENT = "已发送待确认"
DELIVERY_DELIVERED = "已送达"
DELIVERY_FAILED = "发送失败"

CORRECTION_PENDING = "待派发"
CORRECTION_DELIVERED = "已送达"
CORRECTION_SENT = "已发送待确认"


# ---------- 时间窗 ----------

def window_start(occurred_at: datetime, window_minutes: int) -> datetime:
    """把发生时间对齐到固定长度窗口的起点（窗口左闭右开）。"""
    if window_minutes <= 0:
        raise ValueError("window_minutes 必须为正整数")
    anchor = occurred_at.replace(second=0, microsecond=0)
    if window_minutes < 60:
        minute = (anchor.minute // window_minutes) * window_minutes
        return anchor.replace(minute=minute)
    anchor = anchor.replace(minute=0)
    hour = (anchor.hour // (window_minutes // 60)) * (window_minutes // 60)
    return anchor.replace(hour=hour)


def window_bounds(occurred_at: datetime, window_minutes: int) -> tuple[datetime, datetime]:
    start = window_start(occurred_at, window_minutes)
    return start, start + timedelta(minutes=window_minutes)


def make_event_identity(
    *, source_id: str, line_number: int, occurred_at: datetime, original_line: str,
) -> str:
    """原始事件身份：同一来源、同一行号、同一发生时间的原始行重传时保持不变。"""
    raw = "|".join([
        str(source_id or ""),
        str(line_number or 0),
        occurred_at.isoformat(),
        original_line or "",
    ])
    return "EVT-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ---------- 数据结构 ----------

@dataclass
class AlertEvent:
    """进入窗口检测的一条事件，``event_id`` 就是它在告警/更正链路里的身份。"""

    event_id: str
    event_type_id: str
    occurred_at: datetime
    original_line: str
    source_id: str = ""
    line_number: int = 0
    fields: dict[str, Any] = field(default_factory=dict)
    received_at: datetime | None = None
    retransmissions: int = 0
    corrected: bool = False
    corrected_from_type: str = ""
    correction_reason: str = ""
    source_record: Any = field(default=None, repr=False, compare=False)

    def identity(self) -> dict[str, Any]:
        """输出给转发包使用的原事件身份。"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type_id,
            "occurred_at": self.occurred_at.isoformat(),
            "source_id": self.source_id,
            "line_number": self.line_number,
            "original_line": self.original_line,
            "corrected": self.corrected,
            "corrected_from_type": self.corrected_from_type,
        }


@dataclass
class WindowEvaluation:
    """一次窗口核验的快照——check_anomaly 的核实结果。"""

    window_id: str
    event_type_id: str
    window_start: datetime
    window_end: datetime
    threshold: int
    count: int
    event_ids: list[str]
    evidence: list[dict[str, Any]]
    triggered: bool
    evaluated_at: datetime
    closed: bool
    retransmissions: int = 0
    alerted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "event_type": self.event_type_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "threshold": self.threshold,
            "count": self.count,
            "event_ids": list(self.event_ids),
            "evidence": copy.deepcopy(self.evidence),
            "triggered": self.triggered,
            "evaluated_at": self.evaluated_at.isoformat(),
            "closed": self.closed,
            "retransmissions": self.retransmissions,
            "alerted": self.alerted,
        }


@dataclass
class WindowAlert:
    """一个达到门槛的时间窗在某个转发目标上的告警批次。"""

    alert_id: str
    window_id: str
    event_type_id: str
    target: str
    threshold: int
    count: int
    window_start: datetime
    window_end: datetime
    event_ids: list[str]
    evidence: list[dict[str, Any]]
    triggered_at: datetime
    state: str = ALERT_PENDING
    package: dict[str, Any] = field(default_factory=dict)
    delivery_id: str | None = None
    correction_ids: list[str] = field(default_factory=list)
    claimed_round: str | None = None
    withdrawal_reason: str = ""
    rearmed_from: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "window_id": self.window_id,
            "event_type": self.event_type_id,
            "target": self.target,
            "threshold": self.threshold,
            "count": self.count,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "event_ids": list(self.event_ids),
            "state": self.state,
            "package_id": self.package.get("package_id"),
            "delivery_id": self.delivery_id,
            "correction_ids": list(self.correction_ids),
            "claimed_round": self.claimed_round,
            "withdrawal_reason": self.withdrawal_reason,
        }


@dataclass
class DeliveryRecord:
    """一次转发交付：目标侧回执与本端登记分开记录。"""

    delivery_id: str
    kind: str  # alert / correction
    target: str
    package_id: str
    alert_id: str
    correction_id: str | None = None
    state: str = DELIVERY_PENDING
    claimed_round: str | None = None
    sent_at: datetime | None = None
    registered_at: datetime | None = None
    receipt_id: str | None = None
    attempts: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "kind": self.kind,
            "target": self.target,
            "package_id": self.package_id,
            "alert_id": self.alert_id,
            "correction_id": self.correction_id,
            "state": self.state,
            "claimed_round": self.claimed_round,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "receipt_id": self.receipt_id,
            "attempts": self.attempts,
        }


@dataclass
class CorrectionRecord:
    """把已送达告警更正为"不再达门槛"的交付记录。"""

    correction_id: str
    alert_id: str
    window_id: str
    target: str
    original_package_id: str
    reason: str
    threshold: int
    count: int
    original_event_ids: list[str]
    retained_event_ids: list[str]
    withdrawn_event_ids: list[str]
    evidence: list[dict[str, Any]]
    created_at: datetime
    state: str = CORRECTION_PENDING
    package: dict[str, Any] = field(default_factory=dict)
    delivery_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "correction_id": self.correction_id,
            "alert_id": self.alert_id,
            "ref_alert_id": self.alert_id,
            "window_id": self.window_id,
            "target": self.target,
            "original_package_id": self.original_package_id,
            "reason": self.reason,
            "threshold": self.threshold,
            "count": self.count,
            "original_event_ids": list(self.original_event_ids),
            "retained_event_ids": list(self.retained_event_ids),
            "withdrawn_event_ids": list(self.withdrawn_event_ids),
            "state": self.state,
            "package_id": self.package.get("package_id"),
            "delivery_id": self.delivery_id,
        }


@dataclass
class ClaimRound:
    """一轮领取结果：本轮允许派发的告警范围。"""

    round_id: str
    target: str | None
    created_at: datetime
    alert_ids: list[str]
    correction_ids: list[str] = field(default_factory=list)
    dispatched: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "round_id": self.round_id,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "alert_ids": list(self.alert_ids),
            "correction_ids": list(self.correction_ids),
            "dispatched": self.dispatched,
        }


class InMemoryForwardTransport:
    """模拟下游接收端：自己留一份"实际收到"的回执台账。

    它与引擎的本端登记互不影响，因此可以表达"目标已收到、本端未登记就中断"。
    """

    def __init__(self) -> None:
        self.receipts: dict[str, dict[str, Any]] = {}
        self.received_order: list[str] = []
        self._lock = threading.Lock()

    def send(self, package: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        receipt_id = f"RCPT-{package.get('package_id', 'UNKNOWN')}"
        receipt = {
            "receipt_id": receipt_id,
            "package_id": package.get("package_id"),
            "target": package.get("target"),
            "kind": package.get("kind", "alert"),
            "alert_id": package.get("alert_id"),
            "correction_id": package.get("correction_id"),
            "received_at": (now or datetime.now()).isoformat(),
            "payload": copy.deepcopy(package),
        }
        with self._lock:
            self.receipts[receipt_id] = receipt
            self.received_order.append(receipt_id)
        return receipt

    def find_by_package(self, package_id: str) -> dict[str, Any] | None:
        receipt_id = f"RCPT-{package_id}"
        with self._lock:
            return copy.deepcopy(self.receipts.get(receipt_id))

    def packages(self) -> list[dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(self.receipts[rid]) for rid in self.received_order]


# ---------- 引擎 ----------

class AlertForwardEngine:
    """按时间窗检测阈值，并驱动待派发清单和幂等转发的内存引擎。"""

    def __init__(
        self,
        *,
        window_minutes: int = 5,
        threshold: int = 3,
        target: str = "default",
        transport: InMemoryForwardTransport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.window_minutes = window_minutes
        self._rules: dict[str, dict[str, Any]] = {}
        self._events: dict[str, AlertEvent] = {}
        self._buckets: dict[datetime, list[str]] = {}
        self._alerts: dict[str, WindowAlert] = {}
        self._corrections: dict[str, CorrectionRecord] = {}
        self._deliveries: dict[str, DeliveryRecord] = {}
        self._rounds: dict[str, ClaimRound] = {}
        self.transport = transport or InMemoryForwardTransport()
        self._clock = clock or datetime.now
        self._seq = 0
        self.retransmissions: list[dict[str, Any]] = []
        self.last_ingest: dict[str, Any] = {}
        # 窗口规则按事件类型分别配置，未配置的类型继承默认规则。
        self._rules["*"] = {
            "threshold": max(0, int(threshold)),
            "target": target,
            "window_minutes": window_minutes,
        }

    # ----- 基础工具 -----

    def now(self) -> datetime:
        return self._clock()

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq:04d}"

    def configure(
        self,
        *,
        event_type_id: str | None,
        threshold: int | None = None,
        target: str | None = None,
        window_minutes: int | None = None,
    ) -> dict[str, Any]:
        """配置某事件类型的窗口规则；``event_type_id=None`` 时作为默认规则。"""
        key = event_type_id or "*"
        rule = self._rules.setdefault(key, {})
        if threshold is not None:
            rule["threshold"] = max(0, int(threshold))
        if target is not None:
            rule["target"] = target
        if window_minutes is not None:
            if window_minutes <= 0:
                raise ValueError("window_minutes 必须为正整数")
            rule["window_minutes"] = int(window_minutes)
            if key == "*":
                self.window_minutes = int(window_minutes)
        for field_name, fallback in (
            ("threshold", 3), ("target", "default"), ("window_minutes", self.window_minutes),
        ):
            if field_name not in rule:
                inherited = self._rules.get("*", {})
                rule[field_name] = inherited.get(field_name, fallback)
        return dict(rule)

    def default_rule(self) -> dict[str, Any]:
        base = self._rules.get("*", {})
        return {
            "threshold": int(base.get("threshold", 3)),
            "target": str(base.get("target", "default")),
            "window_minutes": int(base.get("window_minutes", self.window_minutes)),
        }

    def rule_for(self, event_type_id: str, **overrides: Any) -> dict[str, Any]:
        rule = dict(self.default_rule())
        rule.update(self._rules.get(event_type_id, {}))
        for key in ("threshold", "target", "window_minutes"):
            if overrides.get(key) is not None:
                rule[key] = overrides[key]
        if int(rule["window_minutes"]) <= 0:
            raise ValueError("window_minutes 必须为正整数")
        return rule

    def _window_id(self, event_type_id: str, start: datetime) -> str:
        return f"{event_type_id}@{start.strftime('%Y-%m-%dT%H:%M')}"

    # 公开的窗口工具，供服务层与采集管道复用，避免依赖私有方法。
    def window_id(self, event_type_id: str, start: datetime) -> str:
        return self._window_id(event_type_id, start)

    def known_window_ids(self) -> list[str]:
        return self._known_window_ids()

    def get_event(self, event_id: str) -> AlertEvent | None:
        with self._lock:
            return self._events.get(event_id)

    def _is_closed(self, end: datetime, now: datetime) -> bool:
        try:
            return now >= end
        except TypeError:
            # 一个带时区一个不带时，退化为按墙上时间比较。
            return now.replace(tzinfo=None) >= end.replace(tzinfo=None)

    def _window_events(self, event_type_id: str, start: datetime, end: datetime) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for event_id in self._buckets.get(start, []):
            event = self._events[event_id]
            # 更正后事件会改属另一事件类型，不再属于原窗口。
            if event.event_type_id != event_type_id:
                continue
            if start <= event.occurred_at < end:
                events.append(event)
        events.sort(key=lambda item: (item.occurred_at, item.event_id))
        return events

    @staticmethod
    def _evidence(events: Iterable[AlertEvent]) -> tuple[list[str], list[dict[str, Any]]]:
        event_list = list(events)
        return [e.event_id for e in event_list], [e.identity() for e in event_list]

    # ----- 事件进入与窗口核验 -----

    def ingest_event(
        self,
        *,
        event_type_id: str,
        occurred_at: datetime,
        original_line: str,
        event_id: str | None = None,
        source_id: str = "",
        line_number: int = 0,
        fields: dict[str, Any] | None = None,
        received_at: datetime | None = None,
    ) -> AlertEvent:
        """登记一条事件；同一原始事件身份重传时只累计重传次数，不增加窗口计数。"""
        occurred_at = occurred_at or self.now()
        received_at = received_at or self.now()
        identity = event_id or make_event_identity(
            source_id=source_id, line_number=line_number,
            occurred_at=occurred_at, original_line=original_line,
        )
        with self._lock:
            existing = self._events.get(identity)
            if existing is not None:
                existing.retransmissions += 1
                existing.received_at = received_at
                record = {
                    "event_id": identity,
                    "event_type": existing.event_type_id,
                    "occurred_at": existing.occurred_at.isoformat(),
                    "received_at": received_at.isoformat(),
                    "counted": False,
                    "retransmissions": existing.retransmissions,
                }
                self.retransmissions.append(record)
                self.last_ingest = record
                return existing

            event = AlertEvent(
                event_id=identity,
                event_type_id=event_type_id,
                occurred_at=occurred_at,
                original_line=original_line,
                source_id=source_id,
                line_number=line_number,
                fields=dict(fields or {}),
                received_at=received_at,
            )
            self._events[identity] = event
            rule_window = int(self.rule_for(event_type_id)["window_minutes"])
            start = window_start(occurred_at, rule_window)
            self._buckets.setdefault(start, []).append(identity)
            self.last_ingest = {
                "event_id": identity,
                "event_type": event_type_id,
                "occurred_at": occurred_at.isoformat(),
                "received_at": received_at.isoformat(),
                "window_start": start.isoformat(),
                "counted": True,
                "retransmissions": 0,
            }
            return event

    def ingest_records(
        self,
        records: Iterable[Any],
        *,
        received_at: datetime | None = None,
        event_type_of: Callable[[Any], str] | None = None,
    ) -> list[AlertEvent]:
        """把 EventRecord 或普通映射登记进窗口引擎。"""
        ingested: list[AlertEvent] = []
        for record in records:
            event = self.ingest_record(
                record, received_at=received_at, event_type_of=event_type_of)
            if event is not None:
                ingested.append(event)
        return ingested

    def ingest_record(
        self,
        record: Any,
        *,
        received_at: datetime | None = None,
        event_type_of: Callable[[Any], str] | None = None,
    ) -> AlertEvent | None:
        event_type_id, occurred_at, original_line, source_id, line_number, fields, record_id = (
            self._record_parts(record, event_type_of)
        )
        if event_type_id is None or occurred_at is None:
            return None
        event = self.ingest_event(
            event_type_id=event_type_id,
            occurred_at=occurred_at,
            original_line=original_line,
            event_id=record_id,
            source_id=source_id,
            line_number=line_number,
            fields=fields,
            received_at=received_at,
        )
        event.source_record = record
        return event

    @staticmethod
    def _record_parts(record: Any, event_type_of: Callable[[Any], str] | None):
        if isinstance(record, AlertEvent):
            return (
                record.event_type_id, record.occurred_at, record.original_line,
                record.source_id, record.line_number, record.fields, record.event_id,
            )
        if isinstance(record, dict):
            event_type_id = record.get("event_type") or record.get("event_type_id")
            if isinstance(event_type_id, dict):
                event_type_id = event_type_id.get("type_id") or event_type_id.get("id")
            occurred_at = record.get("occurred_at") or record.get("event_time")
            if isinstance(occurred_at, str):
                occurred_at = datetime.fromisoformat(occurred_at)
            return (
                event_type_id, occurred_at, str(record.get("original_line")
                                                   or record.get("original_content") or ""),
                str(record.get("source_id") or ""), int(record.get("line_number") or 0),
                dict(record.get("fields") or record.get("parsed_fields") or {}),
                record.get("event_id") or record.get("record_id"),
            )
        # EventRecord：身份由原始内容 + 发生时间 + 来源主机确定，
        # 这样同一原始行重传不会因为 record_id 重置而被当成新事件。
        event_type = getattr(record, "event_type", None)
        type_id = getattr(event_type, "type_id", None) or str(event_type or "")
        if event_type_of is not None:
            type_id = event_type_of(record)
        occurred_at = getattr(record, "event_time", None)
        original_line = getattr(record, "original_content", "") or ""
        source_host = getattr(record, "source_host", "") or ""
        line_number = getattr(record, "line_number", 0) or 0
        identity = make_event_identity(
            source_id=source_host, line_number=line_number,
            occurred_at=occurred_at, original_line=original_line,
        ) if occurred_at is not None else getattr(record, "record_id", None)
        return (
            type_id, occurred_at, original_line, source_host, line_number,
            dict(getattr(record, "parsed_fields", {}) or {}), identity,
        )

    def evaluate_window(
        self,
        window_id: str,
        *,
        threshold: int | None = None,
        target: str | None = None,
        now: datetime | None = None,
        create_alert: bool = True,
    ) -> dict[str, Any] | None:
        """核验一个窗口是否达到门槛；只有达到门槛才创建/更新告警批次。"""
        with self._lock:
            event_type_id, start = self._split_window_id(window_id)
            if event_type_id is None or start is None:
                return None
            rule = self.rule_for(event_type_id, threshold=threshold, target=target)
            start = window_start(start, int(rule["window_minutes"]))
            end = start + timedelta(minutes=int(rule["window_minutes"]))
            canonical_id = self._window_id(event_type_id, start)
            known_alert = self.find_alert(window_id=canonical_id)
            events = self._window_events(event_type_id, start, end)
            event_ids, evidence = self._evidence(events)
            current_now = now or self.now()
            triggered = len(events) >= int(rule["threshold"])
            evaluation = WindowEvaluation(
                window_id=canonical_id,
                event_type_id=event_type_id,
                window_start=start,
                window_end=end,
                threshold=int(rule["threshold"]),
                count=len(events),
                event_ids=event_ids,
                evidence=evidence,
                triggered=triggered,
                evaluated_at=current_now,
                closed=self._is_closed(end, current_now),
                retransmissions=sum(e.retransmissions for e in events),
                alerted=known_alert is not None and known_alert.state != ALERT_WITHDRAWN,
            )
            if triggered and create_alert:
                alert = self._ensure_alert(evaluation, str(rule["target"]))
                evaluation.alerted = alert.state != ALERT_WITHDRAWN
            return evaluation.as_dict()

    @staticmethod
    def _split_window_id(window_id: str) -> tuple[str | None, datetime | None]:
        if "@" not in window_id:
            return None, None
        event_type_id, stamp = window_id.rsplit("@", 1)
        try:
            return event_type_id, datetime.fromisoformat(stamp)
        except ValueError:
            return None, None

    def evaluate_all(
        self,
        *,
        now: datetime | None = None,
        threshold: int | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """核验全部已知窗口；这是"检测入口"对外汇报窗口状态的唯一来源。"""
        with self._lock:
            window_ids = self._known_window_ids()
            results = []
            for window_id in window_ids:
                result = self.evaluate_window(
                    window_id, threshold=threshold, target=target, now=now)
                if result is not None:
                    results.append(result)
            return results

    def refresh(
        self,
        *,
        now: datetime | None = None,
        threshold: int | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """``evaluate_all`` 的别名，便于派发前先刷新窗口告警批次。"""
        return self.evaluate_all(now=now, threshold=threshold, target=target)

    def _known_window_ids(self) -> list[str]:
        ids: set[str] = set()
        for event in self._events.values():
            start = window_start(event.occurred_at, int(
                self.rule_for(event.event_type_id)["window_minutes"]))
            ids.add(self._window_id(event.event_type_id, start))
        for alert in self._alerts.values():
            ids.add(alert.window_id)
        return sorted(ids)

    def _ensure_alert(
        self, evaluation: WindowEvaluation, target: str,
    ) -> WindowAlert:
        # 一个时间窗只对应一条告警批次；阈值变化视为同一告警的重新核验。
        alert_id = "ALT-" + hashlib.sha256(evaluation.window_id.encode("utf-8")).hexdigest()[:12]
        existing = self._alerts.get(alert_id)
        if existing is not None:
            undelivered = existing.state == ALERT_PENDING and existing.delivery_id is None
            if undelivered and (
                existing.target != target or existing.threshold != evaluation.threshold
            ):
                # 尚未派发时，转发路由规则确定的目标准许接管告警批次。
                existing.target = target
                existing.threshold = evaluation.threshold
                existing.count = evaluation.count
                existing.event_ids = list(evaluation.event_ids)
                existing.evidence = copy.deepcopy(evaluation.evidence)
                existing.package = self._build_alert_package(existing, evaluation)
            if existing.state == ALERT_WITHDRAWN and evaluation.triggered:
                # 未交付的告警不作废到永久：后续证据再次达门槛时可以重新进入待派发。
                existing.state = ALERT_PENDING
                existing.count = evaluation.count
                existing.event_ids = list(evaluation.event_ids)
                existing.evidence = copy.deepcopy(evaluation.evidence)
                existing.target = target
                existing.threshold = evaluation.threshold
                existing.package = self._build_alert_package(existing, evaluation)
                existing.withdrawal_reason = ""
                existing.rearmed_from = ALERT_WITHDRAWN
            return existing
        alert = WindowAlert(
            alert_id=alert_id,
            window_id=evaluation.window_id,
            event_type_id=evaluation.event_type_id,
            target=target,
            threshold=evaluation.threshold,
            count=evaluation.count,
            window_start=evaluation.window_start,
            window_end=evaluation.window_end,
            event_ids=list(evaluation.event_ids),
            evidence=copy.deepcopy(evaluation.evidence),
            triggered_at=evaluation.evaluated_at,
        )
        alert.package = self._build_alert_package(alert, evaluation)
        self._alerts[alert_id] = alert
        return alert

    def _build_alert_package(
        self, alert: WindowAlert, evaluation: WindowEvaluation,
    ) -> dict[str, Any]:
        package_id = "PKG-ALT-" + hashlib.sha256(
            f"{alert.alert_id}|{evaluation.window_id}|{','.join(evaluation.event_ids)}"
            .encode("utf-8")
        ).hexdigest()[:16]
        return {
            "package_id": package_id,
            "kind": "alert",
            "alert_id": alert.alert_id,
            "window_id": evaluation.window_id,
            "event_type": evaluation.event_type_id,
            "target": alert.target,
            "threshold": evaluation.threshold,
            "count": evaluation.count,
            "window_start": evaluation.window_start.isoformat(),
            "window_end": evaluation.window_end.isoformat(),
            "trigger_basis": {
                "rule": "window_threshold",
                "threshold": evaluation.threshold,
                "count": evaluation.count,
                "window_start": evaluation.window_start.isoformat(),
                "window_end": evaluation.window_end.isoformat(),
                "event_type": evaluation.event_type_id,
                "window_closed": evaluation.closed,
            },
            "event_ids": list(evaluation.event_ids),
            "event_identities": copy.deepcopy(evaluation.evidence),
            "evidence": copy.deepcopy(evaluation.evidence),
            "payload": copy.deepcopy(evaluation.evidence),
        }

    # ----- 告警查询与待派发 -----

    def alerts(self) -> list[WindowAlert]:
        with self._lock:
            return sorted(self._alerts.values(), key=lambda a: (a.window_start, a.alert_id))

    def get_alert(self, alert_id: str) -> WindowAlert | None:
        with self._lock:
            return self._alerts.get(alert_id)

    def find_alert(self, *, window_id: str | None = None,
                   alert_id: str | None = None) -> WindowAlert | None:
        with self._lock:
            if alert_id:
                return self._alerts.get(alert_id)
            if window_id:
                candidates = [a for a in self._alerts.values() if a.window_id == window_id]
                if candidates:
                    return sorted(candidates, key=lambda a: a.alert_id)[0]
            return None

    def pending_alerts(self, *, target: str | None = None) -> list[WindowAlert]:
        with self._lock:
            return [
                alert for alert in sorted(
                    self._alerts.values(), key=lambda a: (a.window_start, a.alert_id))
                if alert.state == ALERT_PENDING and (target is None or alert.target == target)
            ]

    def pending_dispatch_list(self, *, target: str | None = None) -> list[dict[str, Any]]:
        """待派发清单：由达到门槛的窗口告警驱动，而不是原始事件条数。"""
        pending = self.pending_alerts(target=target)
        corrections = self.pending_corrections(target=target)
        items = [
            {
                "type": "alert",
                "alert_id": alert.alert_id,
                "window_id": alert.window_id,
                "target": alert.target,
                "package_id": alert.package.get("package_id"),
                "count": alert.count,
                "threshold": alert.threshold,
            }
            for alert in pending
        ]
        items.extend(
            {
                "type": "correction",
                "correction_id": correction.correction_id,
                "alert_id": correction.alert_id,
                "window_id": correction.window_id,
                "target": correction.target,
                "package_id": correction.package.get("package_id"),
                "count": correction.count,
            }
            for correction in corrections
        )
        return items

    # ----- 领取与派发 -----

    def claim_round(
        self,
        *,
        target: str | None = None,
        limit: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """领取本轮可以发出的告警/更正范围；领取不改变窗口的后续可派发性。"""
        with self._lock:
            round_id = self._next_id("ROUND")
            alerts = self.pending_alerts(target=target)
            corrections = self.pending_corrections(target=target)
            if limit is not None:
                alerts = alerts[:limit]
            alert_ids = [a.alert_id for a in alerts]
            correction_ids = [c.correction_id for c in corrections]
            for alert in alerts:
                alert.claimed_round = round_id
            for correction in corrections:
                correction.package["claimed_round"] = round_id
            record = ClaimRound(
                round_id=round_id,
                target=target,
                created_at=now or self.now(),
                alert_ids=alert_ids,
                correction_ids=correction_ids,
            )
            self._rounds[round_id] = record
            return {
                **record.as_dict(),
                "alerts": [a.as_dict() for a in alerts],
                "corrections": [c.as_dict() for c in corrections],
            }

    def dispatch(
        self,
        *,
        transport: Any | None = None,
        target: str | None = None,
        round_id: str | None = None,
        limit: int | None = None,
        acknowledge: bool = True,
        include_corrections: bool = True,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """派发待发告警（可含更正）；同一窗口告警/同一更正最多发出一次。"""
        transport = transport or self.transport
        current_now = now or self.now()
        results: list[dict[str, Any]] = []
        with self._lock:
            alerts = self._alerts_for_dispatch(target=target, round_id=round_id)
            if limit is not None:
                alerts = alerts[:limit]
            for alert in alerts:
                if alert.state != ALERT_PENDING:
                    continue
                # 把状态原子地切到"已发送待确认"，并发调用时只有一个会继续发包。
                alert.state = ALERT_SENT
                delivery = self._create_delivery(
                    kind="alert", target=alert.target,
                    package=alert.package, alert_id=alert.alert_id,
                    round_id=alert.claimed_round, now=current_now,
                )
                alert.delivery_id = delivery.delivery_id
                try:
                    receipt = transport.send(copy.deepcopy(alert.package), now=current_now)
                except Exception:  # noqa: BLE001 - 发送失败回退为待派发，下一次可重试
                    alert.state = ALERT_PENDING
                    delivery.state = DELIVERY_FAILED
                    delivery.attempts += 1
                    raise
                delivery.attempts += 1
                delivery.sent_at = current_now
                delivery.receipt_id = receipt.get("receipt_id")
                if acknowledge:
                    self._register_delivery(delivery, now=current_now)
                    alert.state = ALERT_DELIVERED
                results.append({
                    **alert.package,
                    "delivery": delivery.as_dict(),
                    "delivered": delivery.state == DELIVERY_DELIVERED,
                    "target_received": receipt is not None,
                })
            if include_corrections:
                corrections = self._corrections_for_dispatch(
                    target=target, round_id=round_id)
                if limit is not None:
                    corrections = corrections[:max(limit - len(results), 0)]
                for correction in corrections:
                    if correction.state != CORRECTION_PENDING:
                        continue
                    correction.state = CORRECTION_SENT
                    delivery = self._create_delivery(
                        kind="correction", target=correction.target,
                        package=correction.package, alert_id=correction.alert_id,
                        correction_id=correction.correction_id,
                        round_id=correction.package.get("claimed_round"),
                        now=current_now,
                    )
                    correction.delivery_id = delivery.delivery_id
                    receipt = transport.send(
                        copy.deepcopy(correction.package), now=current_now)
                    delivery.attempts += 1
                    delivery.sent_at = current_now
                    delivery.receipt_id = receipt.get("receipt_id")
                    if acknowledge:
                        self._register_delivery(delivery, now=current_now)
                        correction.state = CORRECTION_DELIVERED
                    results.append({
                        **correction.package,
                        "delivery": delivery.as_dict(),
                        "delivered": delivery.state == DELIVERY_DELIVERED,
                        "target_received": receipt is not None,
                    })
        return results

    def dispatch_pending(self, **kwargs: Any) -> list[dict[str, Any]]:
        """``dispatch`` 的别名：派发当前待派发清单。"""
        return self.dispatch(**kwargs)

    def _alerts_for_dispatch(
        self, *, target: str | None, round_id: str | None,
    ) -> list[WindowAlert]:
        rounds = [self._rounds[round_id]] if round_id in self._rounds else []
        alerts = [
            alert for alert in sorted(
                self._alerts.values(), key=lambda a: (a.window_start, a.alert_id))
            if alert.state == ALERT_PENDING and (target is None or alert.target == target)
        ]
        if rounds:
            # 本轮只能派出领取时圈定的告警范围，晚到补进前窗的告警不在本轮之内。
            allowed = set(rounds[0].alert_ids)
            alerts = [a for a in alerts if a.alert_id in allowed]
            rounds[0].dispatched = True
        elif round_id is not None:
            alerts = []
        return alerts

    def _create_delivery(
        self,
        *,
        kind: str,
        target: str,
        package: dict[str, Any],
        alert_id: str,
        correction_id: str | None = None,
        round_id: str | None,
        now: datetime,
    ) -> DeliveryRecord:
        key = f"{kind}|{alert_id}|{correction_id or ''}|{package.get('package_id')}"
        delivery_id = "DLV-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:14]
        existing = self._deliveries.get(delivery_id)
        if existing is not None:
            if existing.state != DELIVERY_DELIVERED:
                existing.claimed_round = round_id
            return existing
        delivery = DeliveryRecord(
            delivery_id=delivery_id,
            kind=kind,
            target=target,
            package_id=str(package.get("package_id")),
            alert_id=alert_id,
            correction_id=correction_id,
            state=DELIVERY_PENDING,
            claimed_round=round_id,
        )
        self._deliveries[delivery_id] = delivery
        return delivery

    def _register_delivery(self, delivery: DeliveryRecord, *, now: datetime) -> None:
        delivery.state = DELIVERY_DELIVERED
        delivery.registered_at = now

    def deliveries(self, *, kind: str | None = None) -> list[DeliveryRecord]:
        with self._lock:
            items = sorted(self._deliveries.values(), key=lambda d: d.delivery_id)
            if kind is not None:
                items = [d for d in items if d.kind == kind]
            return items

    # ----- 更正：原行更正后不再达门槛 -----

    def correct_event(
        self,
        event_id: str,
        *,
        new_event_type_id: str = "EVEN-0001",
        reason: str = "原行更正",
        now: datetime | None = None,
        auto_dispatch: bool = False,
        transport: Any | None = None,
    ) -> dict[str, Any]:
        """把一条事件更正为其他事件类型，并重算它涉及的窗口。

        对已经实际送达的告警，生成一条指向同一目标的更正包（保留原事件身份）；
        未送达的告警只登记撤回，不产生转发。同一更正重复送入只交付一次。
        """
        current_now = now or self.now()
        with self._lock:
            event = self._events.get(event_id)
            if event is None:
                raise KeyError(f"事件 {event_id} 不存在")
            old_type = event.corrected_from_type or event.event_type_id
            already_corrected = event.corrected and event.event_type_id == new_event_type_id
            previous_type = event.event_type_id
            event.corrected = True
            event.corrected_from_type = old_type
            event.event_type_id = new_event_type_id
            event.correction_reason = reason
            rule_window = int(self.rule_for(old_type)["window_minutes"])
            old_start = window_start(event.occurred_at, rule_window)
            old_window_id = self._window_id(old_type, old_start)

            corrections: list[CorrectionRecord] = []
            affected: list[dict[str, Any]] = []
            for alert in list(self._alerts.values()):
                if alert.window_id != old_window_id:
                    continue
                evaluation = self.evaluate_window(
                    old_window_id, threshold=alert.threshold, target=alert.target,
                    now=current_now, create_alert=False)
                if evaluation is None:
                    continue
                if not already_corrected:
                    affected.append(evaluation)
                if evaluation["count"] >= alert.threshold:
                    # 仍然达门槛：不需要更正，告警照原样保留。
                    continue
                if alert.state == ALERT_DELIVERED or self._alert_was_delivered(alert):
                    correction = self._ensure_correction(
                        alert, evaluation, reason=reason, now=current_now)
                    if correction.correction_id not in alert.correction_ids:
                        alert.correction_ids.append(correction.correction_id)
                    corrections.append(correction)
                else:
                    # 未实际送达：保留告警记录并登记撤回，绝不悄悄删除。
                    alert.state = ALERT_WITHDRAWN
                    alert.withdrawal_reason = reason
            if auto_dispatch and corrections:
                self.dispatch(transport=transport, now=current_now,
                              include_corrections=True)
            return {
                "event_id": event_id,
                "from_event_type": old_type,
                "previous_event_type": previous_type,
                "to_event_type": new_event_type_id,
                "reason": reason,
                "window_id": old_window_id,
                "windows": affected,
                "alert_ids": [a.alert_id for a in self._alerts.values()
                              if a.window_id == old_window_id],
                "corrections": [c.as_dict() for c in corrections],
                "duplicate_correction": already_corrected,
                "auto_dispatched": auto_dispatch,
            }

    def _alert_was_delivered(self, alert: WindowAlert) -> bool:
        """实际送达 = 目标侧有回执，或本端已登记送达。"""
        if alert.delivery_id:
            delivery = self._deliveries.get(alert.delivery_id)
            if delivery is not None and delivery.state == DELIVERY_DELIVERED:
                return True
        receipt = self.transport.find_by_package(str(alert.package.get("package_id")))
        return receipt is not None

    def _ensure_correction(
        self,
        alert: WindowAlert,
        evaluation: dict[str, Any],
        *,
        reason: str,
        now: datetime,
    ) -> CorrectionRecord:
        current_ids = list(evaluation["event_ids"])
        shipped = [eid for eid in alert.event_ids if eid not in current_ids]
        retained = [eid for eid in alert.event_ids if eid in current_ids]
        identities = []
        for event_id in alert.event_ids:
            stored = self._events.get(event_id)
            if stored is None:
                identities.append(next(
                    (item for item in alert.evidence
                     if item.get("event_id") == event_id), {"event_id": event_id}))
            else:
                identities.append(stored.identity())
        fingerprint = "|".join([
            alert.alert_id,
            str(alert.threshold),
            str(len(current_ids)),
            ",".join(sorted(current_ids)),
            reason,
        ])
        correction_id = "COR-" + hashlib.sha256(
            fingerprint.encode("utf-8")).hexdigest()[:14]
        existing = self._corrections.get(correction_id)
        if existing is not None:
            return existing
        package = {
            "package_id": "PKG-COR-" + hashlib.sha256(
                correction_id.encode("utf-8")).hexdigest()[:16],
            "kind": "correction",
            "correction_id": correction_id,
            "alert_id": alert.alert_id,
            "ref_alert_id": alert.alert_id,
            "original_package_id": alert.package.get("package_id"),
            "window_id": alert.window_id,
            "event_type": alert.event_type_id,
            "target": alert.target,
            "reason": reason,
            "notice": "撤回门槛告警",
            "threshold": alert.threshold,
            "count": len(current_ids),
            "window_start": alert.window_start.isoformat(),
            "window_end": alert.window_end.isoformat(),
            "trigger_basis": {
                "rule": "window_threshold_withdrawn",
                "threshold": alert.threshold,
                "count": len(current_ids),
                "below_threshold": True,
                "original_alert_id": alert.alert_id,
            },
            # 保留原事件身份：原包中的事件、仍保留的事件、被更正掉的事件都可追溯。
            "original_event_ids": list(alert.event_ids),
            "retained_event_ids": retained,
            "withdrawn_event_ids": shipped,
            "event_ids": list(current_ids),
            "event_identities": identities,
            "evidence": copy.deepcopy(evaluation["evidence"]),
            "payload": copy.deepcopy(evaluation["evidence"]),
        }
        correction = CorrectionRecord(
            correction_id=correction_id,
            alert_id=alert.alert_id,
            window_id=alert.window_id,
            target=alert.target,
            original_package_id=str(alert.package.get("package_id")),
            reason=reason,
            threshold=alert.threshold,
            count=len(current_ids),
            original_event_ids=list(alert.event_ids),
            retained_event_ids=retained,
            withdrawn_event_ids=shipped,
            evidence=copy.deepcopy(evaluation["evidence"]),
            created_at=now,
            package=package,
        )
        self._corrections[correction_id] = correction
        return correction

    def corrections(self) -> list[CorrectionRecord]:
        with self._lock:
            return sorted(self._corrections.values(),
                          key=lambda c: (c.created_at, c.correction_id))

    def pending_corrections(self, *, target: str | None = None) -> list[CorrectionRecord]:
        with self._lock:
            return [
                c for c in sorted(
                    self._corrections.values(), key=lambda c: (c.created_at, c.correction_id))
                if c.state == CORRECTION_PENDING and (target is None or c.target == target)
            ]

    def _corrections_for_dispatch(
        self, *, target: str | None, round_id: str | None,
    ) -> list[CorrectionRecord]:
        items = self.pending_corrections(target=target)
        if round_id is not None:
            round_record = self._rounds.get(round_id)
            if round_record is None:
                return []
            allowed = set(round_record.correction_ids)
            items = [c for c in items if c.correction_id in allowed]
        return items

    # ----- 送达核对与重开告警 -----

    def reconcile_alert(self, alert_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        """重开原告警时核清实际送达事实：以目标回执为准，不重复发旧包。"""
        current_now = now or self.now()
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                raise KeyError(f"告警 {alert_id} 不存在")
            delivery = self._deliveries.get(alert.delivery_id) if alert.delivery_id else None
            receipt = self.transport.find_by_package(str(alert.package.get("package_id")))
            if receipt is not None and (delivery is None or delivery.state != DELIVERY_DELIVERED):
                if delivery is None:
                    delivery = self._create_delivery(
                        kind="alert", target=alert.target, package=alert.package,
                        alert_id=alert.alert_id, round_id=alert.claimed_round,
                        now=current_now,
                    )
                    alert.delivery_id = delivery.delivery_id
                delivery.state = DELIVERY_DELIVERED
                delivery.receipt_id = receipt.get("receipt_id")
                delivery.registered_at = current_now
                alert.state = ALERT_DELIVERED
            elif receipt is None and delivery is not None \
                    and delivery.state == DELIVERY_SENT:
                # 本端发过但目标没有回执，不能算送达；回到待派发，可安全重试。
                delivery.state = DELIVERY_FAILED
                alert.state = ALERT_PENDING
            if receipt is not None and alert.state == ALERT_WITHDRAWN:
                # 撤回只说明本端没登记，目标其实已经收到，恢复为已送达。
                alert.state = ALERT_DELIVERED
            if receipt is not None:
                # 重开时按当前证据补建更正：现在不达门槛不能成为取消更正的理由。
                evaluation = self.evaluate_window(
                    alert.window_id, threshold=alert.threshold, target=alert.target,
                    now=current_now, create_alert=False)
                if evaluation is not None and evaluation["count"] < alert.threshold \
                        and not alert.correction_ids:
                    correction = self._ensure_correction(
                        alert, evaluation, reason="重开核对：窗口已不达门槛",
                        now=current_now)
                    alert.correction_ids.append(correction.correction_id)
            corrections = [
                self._corrections[cid].as_dict()
                for cid in alert.correction_ids if cid in self._corrections
            ]
            return {
                "alert_id": alert.alert_id,
                "window_id": alert.window_id,
                "target": alert.target,
                "target_received": receipt is not None,
                "registered": alert.state == ALERT_DELIVERED,
                "alert_state": alert.state,
                "delivery": delivery.as_dict() if delivery else None,
                "package_id": alert.package.get("package_id"),
                "corrections": corrections,
                "pending_correction_ids": [
                    c.correction_id for c in self._corrections.values()
                    if c.alert_id == alert.alert_id and c.state != CORRECTION_DELIVERED
                ],
            }

    def reopen_alert(self, alert_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        return self.reconcile_alert(alert_id, now=now)

    def recompute_alert(self, alert_id: str) -> dict[str, Any]:
        """用原告警里保存的原始日志重算触发依据，不受后续更正影响。"""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                raise KeyError(f"告警 {alert_id} 不存在")
            event_ids = list(alert.event_ids)
            evidence = copy.deepcopy(alert.evidence)
            count = len(event_ids)
            triggered = count >= alert.threshold
            return {
                "alert_id": alert.alert_id,
                "window_id": alert.window_id,
                "threshold": alert.threshold,
                "count": count,
                "triggered": triggered,
                "event_ids": event_ids,
                "evidence": evidence,
                "original_package_id": alert.package.get("package_id"),
                "matches_original": (
                    count >= alert.threshold
                    and count == alert.count
                    and event_ids == list(alert.package.get("event_ids", []))
                ),
                "source": "stored_original_lines",
            }

    # ----- 汇总视图 -----

    def window_report(self) -> list[dict[str, Any]]:
        """从检测入口核对所有窗口：计数、阈值、是否触发、重传与送达状态。"""
        with self._lock:
            reports: list[dict[str, Any]] = []
            for window_id in self._known_window_ids():
                evaluation = self.evaluate_window(window_id, create_alert=False)
                if evaluation is None:
                    continue
                alerts = [a.as_dict() for a in self._alerts.values()
                          if a.window_id == evaluation["window_id"]]
                reports.append({**evaluation, "alerts": alerts})
            return reports

    def retransmission_report(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self.retransmissions)

    def delivery_report(self) -> list[dict[str, Any]]:
        with self._lock:
            return [d.as_dict() for d in self._deliveries.values()]

    def snapshot(self) -> dict[str, Any]:
        """检测入口/测试用的整体快照。"""
        with self._lock:
            return {
                "window_minutes": self.window_minutes,
                "windows": self.window_report(),
                "alerts": [a.as_dict() for a in self.alerts()],
                "corrections": [c.as_dict() for c in self.corrections()],
                "deliveries": self.delivery_report(),
                "retransmissions": self.retransmission_report(),
                "pending": self.pending_dispatch_list(),
                "target_receipts": self.transport.packages(),
            }
