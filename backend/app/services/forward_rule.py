"""转发路由领域服务：读取窗口告警批次，只给达到门槛的窗口派发实际转发包。

每次派发前先领取本轮告警范围，包内携带触发依据（窗口、阈值、计数）和原事件
身份；同一窗口告警在网络重试或并发调用中最多发出一次。更正包关联原告警，
与原告警分别核销。
"""
from __future__ import annotations

from typing import Any

from app.core.alert_registry import get_engine
from app.services.base import BaseModuleService


class ForwardRuleService(BaseModuleService):
    MODULE = "forward_rule"
    ENTITY = "转发规则"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["规则编号", "事件类型", "目标地址", "转发格式", "批量大小", "重试上限", "超时秒数", "规则状态"]
    REQUIRED_FIELDS = ["规则编号", "事件类型", "目标地址"]
    STATUS_ORDER = ["草稿", "生效中", "转发异常", "已停用"]
    ACTION_RULES = {"启效规则": "生效中", "标记异常": "转发异常", "停用规则": "已停用"}
    NEGATIVE_ACTIONS = ["停用规则"]

    # ----- 窗口告警驱动的转发入口 -----

    def claim_round(self, *, target: str | None = None,
                    limit: int | None = None) -> dict[str, Any]:
        """领取本轮允许发出的告警和更正范围。"""
        return get_engine().claim_round(target=target, limit=limit)

    def pending(self, *, target: str | None = None) -> dict[str, Any]:
        engine = get_engine()
        engine.evaluate_all()
        items = engine.pending_dispatch_list(target=target)
        return {
            "items": items,
            "alert_ids": [item["alert_id"] for item in items if item["type"] == "alert"],
            "correction_ids": [
                item["correction_id"] for item in items if item["type"] == "correction"],
        }

    def dispatch(
        self,
        *,
        target: str | None = None,
        round_id: str | None = None,
        acknowledge: bool = True,
        include_corrections: bool = True,
    ) -> list[dict[str, Any]]:
        """派出实际转发包；只有存在达门槛告警批次或待交付更正时才有包。"""
        engine = get_engine()
        engine.evaluate_all()
        return engine.dispatch(
            target=target, round_id=round_id, acknowledge=acknowledge,
            include_corrections=include_corrections,
        )

    def dispatch_round(self, *, target: str | None = None,
                       limit: int | None = None) -> dict[str, Any]:
        """领取并派发一轮，返回本轮实际发出的包（并发时只有一个窗口送达）。"""
        claimed = self.claim_round(target=target, limit=limit)
        packages = self.dispatch(target=target, round_id=claimed["round_id"])
        claimed["packages"] = packages
        claimed["dispatched"] = bool(packages)
        return claimed

    def recompute(self, alert_id: str) -> dict[str, Any]:
        """用原告警保存的原始日志重算触发依据，不受后续更正影响。"""
        return get_engine().recompute_alert(alert_id)

    def reopen(self, alert_id: str) -> dict[str, Any]:
        """重开原告警：核清目标是否实际收到，保留尚未交付的更正。"""
        return get_engine().reopen_alert(alert_id)
