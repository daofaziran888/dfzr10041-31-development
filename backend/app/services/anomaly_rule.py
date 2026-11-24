"""异常告警领域服务：在通用字段/动作骨架之外，提供按发生时间分窗的检测入口。

告警不再按"本次日志事件总数"触发，而是把事件落进固定长度时间窗，逐窗核验
``聚合窗口`` 与 ``触发频次``（作为门槛），只有达到门槛的窗口才生成告警批次。
"""
from __future__ import annotations

from typing import Any

from app.core.alert_registry import get_engine
from app.core.alert_window import window_start
from app.services.base import BaseModuleService


class AnomalyRuleService(BaseModuleService):
    MODULE = "anomaly_rule"
    ENTITY = "告警规则"
    OPERATION_TERM = "聚合"
    LIST_FIELDS = ["规则编号", "事件类型", "检测条件", "告警级别", "触发频次", "聚合窗口", "通知渠道", "规则状态"]
    REQUIRED_FIELDS = ["规则编号", "事件类型", "检测条件"]
    STATUS_ORDER = ["待启用", "生效中", "已触发", "已关闭"]
    ACTION_RULES = {"启用规则": "生效中", "临时关闭": "已触发", "恢复规则": "已关闭"}
    NEGATIVE_ACTIONS = []

    # ----- 按发生时间分窗的检测入口 -----

    def window_settings(self) -> dict[str, Any]:
        engine = get_engine()
        return {
            "window_minutes": engine.window_minutes,
            "default_threshold": engine.default_rule()["threshold"],
            "default_target": engine.default_rule()["target"],
        }

    def check_anomaly(
        self,
        records: list[Any],
        *,
        event_type_id: str,
        threshold: int,
        window_minutes: int | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        """登记事件并核验其所属窗口，返回窗口核实结果。"""
        engine = get_engine()
        engine.configure(
            event_type_id=event_type_id,
            threshold=threshold,
            target=target,
            window_minutes=window_minutes,
        )
        ingested = engine.ingest_records(records)
        windows = []
        for window_id in {self._window_id(event.event_type_id, event) for event in ingested}:
            result = engine.evaluate_window(window_id)
            if result is not None:
                windows.append(result)
        return {
            "rule": self.window_settings(),
            "ingested": [event.identity() for event in ingested],
            "windows": windows,
            "pending": engine.pending_dispatch_list(),
        }

    def window_report(self) -> list[dict[str, Any]]:
        engine = get_engine()
        engine.evaluate_all()
        return engine.window_report()

    def alert_batches(self) -> list[dict[str, Any]]:
        return [alert.as_dict() for alert in get_engine().alerts()]

    @staticmethod
    def _window_id(event_type_id: str, event: Any) -> str:
        start = window_start(event.occurred_at, get_engine().rule_for(event_type_id)["window_minutes"])
        return f"{event_type_id}@{start:%Y-%m-%dT%H:%M}"
