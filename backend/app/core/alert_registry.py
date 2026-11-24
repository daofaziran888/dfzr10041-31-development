"""窗口告警引擎的进程级注册表。

异常告警、转发路由两个领域服务和检测入口共用同一份窗口与送达台账，
避免"窗口端"和"转发端"各记一套账。
"""
from __future__ import annotations

from app.core.alert_window import AlertForwardEngine, InMemoryForwardTransport


def build_engine() -> AlertForwardEngine:
    return AlertForwardEngine(
        window_minutes=5,
        threshold=3,
        target="webhook://alerts.example.com",
        transport=InMemoryForwardTransport(),
    )


ENGINE: AlertForwardEngine = build_engine()


def get_engine() -> AlertForwardEngine:
    return ENGINE


def set_engine(engine: AlertForwardEngine) -> AlertForwardEngine:
    """测试或运维重置共享台账。"""
    global ENGINE
    ENGINE = engine
    return ENGINE
