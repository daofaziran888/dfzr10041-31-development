"""窗口告警与转发检测入口：把按发生时间分窗的告警、待派发清单和送达更正
以独立接口暴露出来，便于从检测入口核对窗口、重传与转发批次。"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.alert_registry import get_engine
from app.core.alert_window import AlertForwardEngine, window_start

router = APIRouter(prefix="/api/alert-window", tags=["窗口告警与转发"])


def _engine() -> AlertForwardEngine:
    """检测入口与领域服务共享同一份窗口/送达台账。"""
    return get_engine()


class EventPayload(BaseModel):
    event_type: str
    occurred_at: datetime
    original_line: str
    event_id: str | None = None
    source_id: str = ""
    line_number: int = 0
    fields: dict[str, Any] = Field(default_factory=dict)


class CorrectionPayload(BaseModel):
    new_event_type: str = "EVEN-0001"
    reason: str = "原行更正为普通访问"
    auto_dispatch: bool = False


class DispatchPayload(BaseModel):
    target: str | None = None
    round_id: str | None = None
    acknowledge: bool = True
    include_corrections: bool = True


class RoundPayload(BaseModel):
    target: str | None = None
    limit: int | None = None


@router.get("/snapshot")
def snapshot() -> dict[str, Any]:
    """整体快照：窗口、告警、更正、送达台账、重传记录与目标回执。"""
    return _engine().snapshot()


@router.get("/windows")
def windows() -> list[dict[str, Any]]:
    """从检测入口核对所有窗口：计数、阈值、触发状态、重传与关联告警。

    汇报前先核验窗口阈值，因此"达到门槛"的窗口一定已经有告警批次。
    """
    _engine().evaluate_all()
    return _engine().window_report()


@router.get("/retransmissions")
def retransmissions() -> list[dict[str, Any]]:
    """重传记录：同一原始事件身份重复送入时只累计次数、不增加窗口计数。"""
    return _engine().retransmission_report()


@router.get("/pending")
def pending(target: str | None = None) -> dict[str, Any]:
    """待派发清单：只由达到门槛的窗口告警和待交付更正驱动。"""
    _engine().evaluate_all()
    items = _engine().pending_dispatch_list(target=target)
    return {
        "items": items,
        "alert_ids": [item["alert_id"] for item in items if item["type"] == "alert"],
        "correction_ids": [
            item["correction_id"] for item in items if item["type"] == "correction"],
    }


@router.post("/events")
def ingest_event(payload: EventPayload) -> dict[str, Any]:
    """登记一条事件；登记后立刻核验它所属的时间窗。"""
    event = _engine().ingest_event(
        event_type_id=payload.event_type,
        occurred_at=payload.occurred_at,
        original_line=payload.original_line,
        event_id=payload.event_id,
        source_id=payload.source_id,
        line_number=payload.line_number,
        fields=payload.fields,
    )
    engine = _engine()
    width = engine.rule_for(event.event_type_id)["window_minutes"]
    begin = window_start(event.occurred_at, width)
    evaluation = engine.evaluate_window(
        f"{event.event_type_id}@{begin:%Y-%m-%dT%H:%M}")
    return {
        "ok": True,
        "event": event.identity(),
        "ingest": engine.last_ingest,
        "window": evaluation,
    }


@router.post("/evaluate")
def evaluate(now: datetime | None = None) -> list[dict[str, Any]]:
    """核验全部窗口阈值；只有达到门槛的窗口才生成告警批次。"""
    return _engine().evaluate_all(now=now)


@router.post("/rounds")
def claim_round(payload: RoundPayload) -> dict[str, Any]:
    """领取本轮允许派发的告警范围；领取顺序与窗口到期顺序相互独立。"""
    return _engine().claim_round(target=payload.target, limit=payload.limit)


@router.post("/dispatch")
def dispatch(payload: DispatchPayload) -> dict[str, Any]:
    """并发安全地派发待发告警；同一窗口告警最多送达一次。"""
    _engine().evaluate_all()
    packages = _engine().dispatch(**payload.model_dump())
    return {
        "ok": True,
        "packages": packages,
        "alert_ids": [item["alert_id"] for item in packages if item.get("kind") == "alert"],
        "correction_ids": [
            item["correction_id"] for item in packages if item.get("kind") == "correction"],
    }


@router.post("/events/{event_id}/correct")
def correct_event(event_id: str, payload: CorrectionPayload) -> dict[str, Any]:
    """原行更正：让仍达门槛的告警保持原样，让已送达告警产生可关联的更正包。"""
    try:
        return _engine().correct_event(
            event_id,
            new_event_type_id=payload.new_event_type,
            reason=payload.reason,
            auto_dispatch=payload.auto_dispatch,
        )
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.post("/alerts/{alert_id}/reopen")
def reopen_alert(alert_id: str) -> dict[str, Any]:
    """重开原告警时核清实际送达事实，必要时补建未交付的更正。"""
    try:
        return _engine().reopen_alert(alert_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/alerts/{alert_id}/recompute")
def recompute_alert(alert_id: str) -> dict[str, Any]:
    """用原告警保存的原始日志重算触发依据。"""
    try:
        return _engine().recompute_alert(alert_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/receipts")
def receipts() -> list[dict[str, Any]]:
    """下游接收端的实际回执台账。"""
    return _engine().transport.packages()
