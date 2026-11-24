"""拾音工坊核心管道：log_source→parser_rule→ingest_job→event_store 端到端采集解析链路。

数据流：原始日志行 → 格式校验 → 正则解析 → 字段提取 → 事件存储
涉及模块：log_source, parser_rule, ingest_job, event_store, batch_checkpoint
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.alert_window import AlertForwardEngine, make_event_identity, window_start
from app.core.models import (
    BatchCheckpoint, EventRecord, EventTypeDef, IngestJob, IngestMetric,
    LogEntry, LogFormat, LogSourceConfig, ParseResultStatus, ParseRule,
    QualityReport,
)

# ---------- 预置日志来源配置 ----------

PRESET_LOG_SOURCES: dict[str, LogSourceConfig] = {
    "access-web": LogSourceConfig(
        source_id="LOG_-0001",
        source_name="WebAccessLog",
        app_label="web-gateway",
        log_path="/var/log/nginx/access.log",
        log_format="access",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "app-backend": LogSourceConfig(
        source_id="LOG_-0002",
        source_name="BackendAppLog",
        app_label="backend-api",
        log_path="/var/log/app/backend.log",
        log_format="app",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "sys-auth": LogSourceConfig(
        source_id="LOG_-0003",
        source_name="SysAuthLog",
        app_label="auth-service",
        log_path="/var/log/auth/syslog",
        log_format="sys",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
}

# ---------- 预置解析规则 ----------

PRESET_PARSE_RULES: list[ParseRule] = [
    ParseRule(
        rule_id="PARS-0001",
        source_id="LOG_-0001",
        regex_pattern=r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+HTTP/\d\.\d"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
        field_names=["client_ip", "time_local", "method", "url", "status", "body_bytes", "referer", "user_agent"],
        time_format="%d/%b/%Y:%H:%M:%S %z",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0002",
        source_id="LOG_-0002",
        regex_pattern=r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+(.*)$',
        field_names=["timestamp", "thread", "level", "logger", "message"],
        time_format="%Y-%m-%d %H:%M:%S.%f",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0003",
        source_id="LOG_-0003",
        regex_pattern=r'^([\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w-]+)\[(\d+)\]:\s+(\w+)\s+(.*)$',
        field_names=["sys_time", "hostname", "process", "pid", "action", "detail"],
        time_format="%b %d %H:%M:%S",
        priority=10,
        state="生效中",
    ),
]

# ---------- 预置事件类型 ----------

PRESET_EVENT_TYPES: dict[str, EventTypeDef] = {
    "access": EventTypeDef(
        type_id="EVEN-0001", type_name="访问事件",
        category_tag="access", severity="INFO",
        sample_ratio=0.5, retain_days=30,
    ),
    "error": EventTypeDef(
        type_id="EVEN-0002", type_name="错误事件",
        category_tag="error", severity="HIGH",
        sample_ratio=1.0, retain_days=90,
    ),
    "auth": EventTypeDef(
        type_id="EVEN-0003", type_name="认证事件",
        category_tag="auth", severity="MEDIUM",
        sample_ratio=1.0, retain_days=60,
    ),
}


@dataclass
class IngestPipelineState:
    """采集管道运行时状态——跨模块数据流的中间产物。"""
    source: LogSourceConfig
    rule: ParseRule
    job: IngestJob
    parsed_logs: list[LogEntry]
    events: list[EventRecord]
    errors: list[dict[str, Any]]
    checkpoints: list[BatchCheckpoint]
    metric: IngestMetric
    quality_report: QualityReport | None = None


class IngestPipeline:
    """核心采集管道：log_source → parser_rule → ingest_job → event_store。

    单次管道执行：
    1. 从 log_source 获取原始日志行
    2. 使用 parser_rule 逐行解析
    3. 通过 ingest_job 控制采集批次
    4. 生成 EventRecord 写入 event_store
    5. 产出 batch_checkpoint 支持断点恢复
    6. 产出 ingest_metric 作为质量报告的数据源
    """

    def __init__(self):
        self._checkpoint_store: dict[str, BatchCheckpoint] = {}
        self._event_store: dict[str, list[EventRecord]] = {}
        self._fingerprint_seen: set[str] = set()
        # 按事件发生时间分窗的告警与转发台账，供 anomaly_rule / forward_rule 共享。
        self.alert_engine: AlertForwardEngine | None = None
        self._pending_alert: EventRecord | None = None

    def ensure_alert_engine(self, **options: Any) -> AlertForwardEngine:
        """惰性创建窗口告警引擎；同一管道实例跨批次共享窗口与送达台账。"""
        if self.alert_engine is None:
            self.alert_engine = AlertForwardEngine(**options)
            return self.alert_engine
        rule = {
            "threshold": options.get("threshold"),
            "target": options.get("target"),
            "window_minutes": options.get("window_minutes"),
        }
        if any(value is not None for value in rule.values()):
            self.alert_engine.configure(event_type_id=None, **rule)
        return self.alert_engine

    # ---------- 数据流 1: log_source → parser_rule → ingest_job → event_store ----------

    def parse_raw_lines(self, source: LogSourceConfig, raw_lines: list[str]) -> list[LogEntry]:
        """用来源配置校验原始日志行格式。"""
        entries: list[LogEntry] = []
        for i, line in enumerate(raw_lines):
            if not line.strip():
                continue
            if not source.match_format(line):
                entries.append(LogEntry(
                    raw_line=line, line_number=i + 1, source_id=source.source_id,
                    parse_status=ParseResultStatus.FORMAT_MISMATCH,
                ))
                continue
            entries.append(LogEntry(
                raw_line=line, line_number=i + 1, source_id=source.source_id,
            ))
        return entries

    def apply_parse_rules(self, entries: list[LogEntry], rule: ParseRule) -> list[LogEntry]:
        """用解析规则从日志条目中提取字段。"""
        for entry in entries:
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                continue
            status, fields = rule.parse(entry.raw_line)
            entry.parse_status = status
            entry.parsed_fields = fields or {}
            entry.checksum = entry.compute_checksum()
        return entries

    def run_ingest_job(self, entries: list[LogEntry], job: IngestJob) -> list[LogEntry]:
        """执行采集作业：按 batch_size 分批，追踪文件游标和跳过行数。"""
        processed: list[LogEntry] = []
        for entry in entries:
            if job.processed_lines >= job.batch_size:
                break
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                job.skipped_lines += 1
                processed.append(entry)
                continue
            job.processed_lines += 1
            job.file_cursor += len(entry.raw_line.encode(job.source_id and "utf-8" or "utf-8"))
            processed.append(entry)
        return processed

    def classify_events(self, entries: list[LogEntry]) -> list[EventRecord]:
        """将解析后的日志条目按事件类型分类并生成 EventRecord。

        数据流入口：event_store ← 解析后的 LogEntry
        分类依据：日志级别（app log → error/access）或来源标识
        """
        records: list[EventRecord] = []
        host_counter: dict[str, int] = {}
        for entry in entries:
            if entry.parse_status != ParseResultStatus.OK or not entry.parsed_fields:
                continue
            event_type = self._classify_entry(entry)
            host = entry.parsed_fields.get("client_ip") or entry.parsed_fields.get("hostname") or "unknown"
            host_counter[host] = host_counter.get(host, 0) + 1
            partition = f"{datetime.now():%Y%m%d}"
            record = EventRecord(
                record_id=f"EVEN-{host_counter[host]:06d}",
                event_type=event_type,
                original_content=entry.raw_line[:500],
                parsed_fields=dict(entry.parsed_fields),
                masked_fields={},
                enriched_fields={},
                event_time=entry.event_time or datetime.now(),
                source_host=host,
                store_partition=partition,
                index_state="已写入",
            )
            records.append(record)
        return records

    def store_events(self, records: list[EventRecord]) -> int:
        """写入 event_store 并返回存储条数。"""
        for record in records:
            self._event_store.setdefault(record.source_host, []).append(record)
        return len(records)

    # ---------- 数据流 2: ingest_job → batch_checkpoint（断点恢复） ----------

    def create_checkpoint(self, job: IngestJob, file_path: str, lines: list[str]) -> BatchCheckpoint:
        """为采集作业创建批次检查点——支持断点恢复。

        记录：文件偏移量、已处理行数、内容校验哈希（用最后 N 行拼接）。
        """
        last_blob = "".join(l.raw_line for l in lines[-5:]) if lines else ""
        content_hash = hashlib.sha256(
            f"{file_path}|{job.file_cursor}|{last_blob}".encode()
        ).hexdigest()[:16]
        checkpoint = BatchCheckpoint(
            checkpoint_id=f"BATC-{job.job_id}-{job.processed_lines:06d}",
            job_id=job.job_id,
            file_path=file_path,
            byte_offset=job.file_cursor,
            line_count=job.processed_lines + job.skipped_lines,
            content_hash=content_hash,
            state="已记录",
        )
        self._checkpoint_store[checkpoint.checkpoint_id] = checkpoint
        return checkpoint

    def resume_from_checkpoint(self, checkpoint: BatchCheckpoint) -> int:
        """从检查点恢复采集：返回应从此偏移量继续的文件位置。"""
        return checkpoint.byte_offset

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def dedup_events(self, records: list[EventRecord], dedup_fields: list[str]) -> list[EventRecord]:
        """对事件记录集合执行去重过滤——对应 dedup_filter 模块。

        使用 SHA256 指纹算法，基于指定的去重字段生成指纹。
        """
        seen: set[str] = set()
        unique: list[EventRecord] = []
        for record in records:
            key_parts = [record.event_type.type_id]
            for field in sorted(dedup_fields):
                val = record.parsed_fields.get(field, "")
                key_parts.append(f"{field}={val}")
            fp = hashlib.sha256("|".join(key_parts).encode()).hexdigest()
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(record)
        return unique

    def sample_events(self, records: list[EventRecord], sample_ratio: float,
                      merge_key: str = "") -> list[EventRecord]:
        """采样归并——对应 sample_job 模块。

        按 sample_ratio 采样，按 merge_key 归并（同 key 仅保留最新）。
        """
        sampled: list[EventRecord] = []
        merged: dict[str, EventRecord] = {}
        threshold = int(len(records) * sample_ratio)
        for i, record in enumerate(records):
            if merge_key:
                mkey = record.parsed_fields.get(merge_key, "")
                if mkey:
                    merged[mkey] = record
            if i < threshold:
                sampled.append(record)
        if merge_key:
            return list(merged.values())
        return sampled

    # ---------- 数据流 6: archive_policy → event_store ----------

    def apply_archive_policy(self, partition: str, retain_days: int) -> list[str]:
        """归档策略：标记超过保留天数的分区为可归档。"""
        to_archive: list[str] = []
        cutoff_date = datetime.now() - __import__("datetime").timedelta(days=retain_days)
        cutoff_int = int(cutoff_date.strftime("%Y%m%d"))
        for host, records in self._event_store.items():
            for record in records:
                try:
                    partition_int = int(record.store_partition) if record.store_partition else 99999999
                except ValueError:
                    continue
                if partition_int < cutoff_int:
                    to_archive.append(record.record_id)
                    record.index_state = "已归档"
        return to_archive

    # ---------- 数据流 7: schema_version → parser_rule ----------

    def detect_schema_change(self, old_fields: list[str], new_fields: list[str]) -> dict[str, Any]:
        """检测Schema版本变更对解析规则的影响。

        返回变更详情：兼容/不兼容判定、新增/删除字段清单、影响事件数。
        """
        old_set = set(old_fields or [])
        new_set = set(new_fields or [])
        added = list(new_set - old_set)
        removed = list(old_set - new_set)
        is_compatible = len(removed) == 0
        affected = sum(
            len(records)
            for records in self._event_store.values()
        )
        return {
            "added_fields": added,
            "removed_fields": removed,
            "is_compatible": is_compatible,
            "affected_event_count": affected,
            "version_time": datetime.now().isoformat(),
        }

    # ---------- 数据流 8: ingest_job → ingest_metric → quality_report ----------

    def compute_ingest_metrics(self, job: IngestJob, elapsed_ms: float,
                                total_lines: int) -> IngestMetric:
        """从采集作业运行状态计算采集指标。

        采集速率 = 处理行数 / 耗时(s)
        错误率 = 跳过行数 / 总行数
        积压行数 = 总行数 - 处理行数
        """
        elapsed_s = max(elapsed_ms / 1000.0, 0.001)
        rate = job.processed_lines / elapsed_s
        error_rate = job.skipped_lines / total_lines if total_lines > 0 else 0.0
        backlog = total_lines - job.processed_lines - job.skipped_lines
        return IngestMetric(
            metric_id=f"INGE-{job.job_id}-{int(time.time())}",
            source_id=job.source_id,
            ingest_rate=round(rate, 2),
            process_delay_ms=round(elapsed_ms, 2),
            error_rate=round(error_rate, 4),
            backlog_lines=max(backlog, 0),
        )

    def generate_quality_report(self, metric: IngestMetric,
                                 parse_ok: int, parse_total: int,
                                 fields_coverage: float,
                                 processed: int = 0,
                                 skipped: int = 0) -> QualityReport:
        """从采集指标生成质量报告——对应 quality_report 模块。

        完整率 = 处理行数 / (处理+跳过)
        解析成功率 = 成功解析行数 / 总处理行数
        字段覆盖率 = 已填充字段数 / 期望字段总数
        """
        total = processed + skipped
        completeness = processed / total if total > 0 else 0.0
        parse_rate = parse_ok / parse_total if parse_total > 0 else 0.0
        return QualityReport(
            report_id=f"QUAL-{metric.metric_id}",
            source_id=metric.source_id,
            completeness_rate=round(completeness, 4),
            parse_success_rate=round(parse_rate, 4),
            field_coverage_rate=round(fields_coverage, 4),
            time_delay_seconds=metric.process_delay_ms / 1000.0,
            eval_period="hourly",
            state="已生成",
        )

    # ---------- 数据流 5: event_type → anomaly_rule → forward_rule ----------

    def check_anomaly(self, records: list[EventRecord], event_type_id: str,
                       threshold: int, *,
                       window_minutes: int | None = None,
                       target: str | None = None,
                       received_at: datetime | None = None,
                       now: datetime | None = None) -> list[EventRecord]:
        """按发生时间分窗核实阈值，返回本次登记后达到门槛的窗口内的记录。

        旧行为（只按本次记录总数打标）不再作为告警依据：计数按 ``event_time``
        落入固定时间窗，重传同一原始行只累计重传次数，不会抬高窗口计数。
        返回值仍限定在本次传入、且属于已触发窗口的记录，方便调用方继续处理。
        """
        engine = self.ensure_alert_engine(
            window_minutes=window_minutes or 5,
            threshold=threshold,
            target=target or "default",
        )
        ingested = [
            event for event in (
                engine.ingest_record(record, received_at=received_at)
                for record in records
            ) if event is not None
        ]
        triggered_window_ids = set()
        for window_id in {self._window_id_of(engine, event) for event in ingested}:
            if not window_id:
                continue
            result = engine.evaluate_window(window_id, now=now)
            if result and result["triggered"]:
                triggered_window_ids.add(window_id)
                if result["event_type"] == event_type_id:
                    self._pending_alert = engine.find_alert(
                        window_id=result["window_id"])
        matched = [r for r in records if r.event_type.type_id == event_type_id]
        flagged = {
            event.event_id for event in ingested
            if self._window_id_of(engine, event) in triggered_window_ids
        }
        for record in matched:
            identity = make_event_identity(
                source_id=getattr(record, "source_host", "") or "",
                line_number=getattr(record, "line_number", 0) or 0,
                occurred_at=record.event_time,
                original_line=getattr(record, "original_content", "") or "",
            )
            if identity in flagged:
                record.parsed_fields["anomaly_alert"] = "triggered"
                record.parsed_fields["anomaly_window"] = self._window_id_of(
                    engine, engine.get_event(identity))
        return matched

    @staticmethod
    def _window_id_of(engine: AlertForwardEngine, event: Any) -> str | None:
        if event is None:
            return None
        occurred_at = getattr(event, "occurred_at", None)
        if occurred_at is None:
            return None
        rule_width = int(engine.rule_for(event.event_type_id)["window_minutes"])
        start = window_start(occurred_at, rule_width)
        return engine.window_id(event.event_type_id, start)

    def apply_forward_rules(self, records: list[EventRecord],
                             target: str, *,
                             event_type_id: str | None = None,
                             threshold: int | None = None,
                             now: datetime | None = None,
                             acknowledge: bool = True) -> list[dict[str, Any]]:
        """只给实际达到门槛的窗口组转发包——对应 forward_rule 模块。

        转发包由窗口告警批次（``alert_engine`` 的待派发清单）驱动，包中带触发
        依据和原事件身份；同一窗口告警并发派发最多发一次。``records`` 只用于
        补齐尚未进入窗口台账的记录，不再以记录条数直接编包。未显式给出阈值时
        沿用告警规则（``check_anomaly``）已经配置的门槛。
        """
        engine = self.ensure_alert_engine(target=target)
        if records:
            engine.ingest_records(records)
        for window_id in engine.known_window_ids():
            engine.evaluate_window(window_id, threshold=threshold, target=target, now=now)
        if event_type_id is not None:
            pending_ids = {
                alert.alert_id for alert in engine.pending_alerts(target=target)
                if alert.event_type_id == event_type_id
            }
            packages = [
                package for package in engine.dispatch(
                    target=target, acknowledge=acknowledge, now=now,
                    include_corrections=False)
                if package.get("alert_id") in pending_ids
            ]
        else:
            packages = engine.dispatch(
                target=target, acknowledge=acknowledge, now=now,
                include_corrections=False)
        return [
            {
                "target": package.get("target"),
                "count": package.get("count"),
                "payload": package.get("event_identities", []),
                "package": package,
            }
            for package in packages
        ]

    def apply_forward_pending(self, *, target: str | None = None,
                              now: datetime | None = None,
                              acknowledge: bool = True) -> list[dict[str, Any]]:
        """派发当前待派发清单（含更正包），返回实际发出的包。"""
        engine = self.ensure_alert_engine()
        return engine.dispatch(target=target, now=now, acknowledge=acknowledge)

    def correct_event(self, event_id: str, *, new_event_type_id: str = "EVEN-0001",
                      reason: str = "原行更正", now: datetime | None = None,
                      auto_dispatch: bool = False) -> dict[str, Any]:
        """原行更正：重算受影响的窗口，已送达的告警交付可关联的更正包。"""
        engine = self.ensure_alert_engine()
        return engine.correct_event(
            event_id, new_event_type_id=new_event_type_id, reason=reason,
            now=now, auto_dispatch=auto_dispatch,
        )

    def reopen_alert(self, alert_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        """重开原告警：以目标回执核清实际送达，并保留待交付的更正。"""
        engine = self.ensure_alert_engine()
        return engine.reopen_alert(alert_id, now=now)

    # ---------- 内部辅助方法 ----------

    def _classify_entry(self, entry: LogEntry) -> EventTypeDef:
        """根据解析字段对日志条目做事件分类。"""
        fields = entry.parsed_fields or {}
        level = fields.get("level", "").upper()
        if level == "ERROR":
            return PRESET_EVENT_TYPES.get("error", PRESET_EVENT_TYPES["access"])
        action = fields.get("action", "").upper()
        if action in ("LOGIN", "LOGOUT", "AUTH", "AUTHENTICATE"):
            return PRESET_EVENT_TYPES.get("auth", PRESET_EVENT_TYPES["access"])
        return PRESET_EVENT_TYPES.get("access", PRESET_EVENT_TYPES["access"])

    def get_event_store(self) -> dict[str, list[EventRecord]]:
        return self._event_store

    def get_checkpoints(self) -> list[BatchCheckpoint]:
        return list(self._checkpoint_store.values())


# ---------- 测试辅助工厂 ----------

def make_sample_raw_lines() -> list[str]:
    """生成用于确定测试的混合日志样本行（包含脏日志、格式不匹配的行）。"""
    return [
        # access 日志
        '192.168.1.10 - - [15/Nov/2026:14:30:05 +0800] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.55 - - [15/Nov/2026:14:30:06 +0800] "POST /api/events/ingest HTTP/1.1" 201 567 "-" "curl/7.88"',
        '172.16.0.3 - - [15/Nov/2026:14:30:07 +0800] "GET /api/health HTTP/1.1" 500 89 "-" "kube-probe/1.28"',
        # app 日志
        '2026-11-15 14:30:05.123 [http-nio-8080-exec-1] INFO  com.example.IngestController - 采集作业 INGE-0001 启动',
        '2026-11-15 14:30:05.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 88',
        '2026-11-15 14:30:05.789 [pool-3-thread-1] DEBUG com.example.CheckpointStore - 检查点 BATC-0001 写入成功',
        '2026-11-15 14:30:06.012 [http-nio-8080-exec-3] WARN  com.example.MaskService - 脱敏规则 MASK-0003 遗漏字段 user_email',
        # 脏日志（格式不匹配）
        '2026-11-15 14:30:06.234 orphan line without proper format',
        '',
        # app 日志 error（重复模式用于测试去重）
        '2026-11-15 14:30:06.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 89',
        # sys 日志
        'Nov 15 14:30:07 auth-server sshd[8891]: LOGIN user=admin from=10.0.0.100',
        'Nov 15 14:30:08 auth-server sshd[8892]: LOGIN user=operator from=192.168.1.50',
        'Nov 15 14:30:09 auth-server sshd[8893]: AUTH failure user=guest reason=password_expired',
        # access 日志（含敏感IP用于脱敏测试）
        '192.168.1.99 - - [15/Nov/2026:14:30:10 +0800] "GET /api/users/13800138000 HTTP/1.1" 200 2000 "-" "Mozilla/5.0"',
        # 脏行（纯数字）
        '2926-16-15 99:99:99.999 [bad] BAD  malformed - 完全不匹配任何格式',
        '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',
    ]


def make_pipeline() -> IngestPipeline:
    """工厂函数：创建一个预配置的采集管道实例。"""
    return IngestPipeline()