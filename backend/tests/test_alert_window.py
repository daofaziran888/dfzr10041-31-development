"""测试：按事件发生时间分窗的告警、转发批次与更正交付。

覆盖场景：
- 五分钟窗内至少 3 条错误才触发；10:00、10:03、10:05 分属两窗
- 重传原行不增加窗口计数，也不把事件挪进别的时间窗
- 窗口已结束、值班员领取下一轮告警后才迟到的事件，仍归入其发生时间窗
- 并发派发同一门槛证据最多发送一次
- 已送达告警因原行更正不再达门槛时，向同一目标交付可关联的更正包
- 目标已收到、本端登记中断时，重开原告警以回执为准
- 未交付的窗口在后续证据再次达门槛时仍可继续派发
"""
from __future__ import annotations

import sys
import os
import threading
import traceback
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.alert_window import (
    ALERT_DELIVERED,
    ALERT_PENDING,
    ALERT_WITHDRAWN,
    AlertForwardEngine,
    InMemoryForwardTransport,
    window_start,
)
from app.core.models import EventRecord, EventTypeDef
from app.core.pipeline import PRESET_EVENT_TYPES, make_pipeline

BASE = datetime(2026, 11, 24, 10, 0, 0)


def at(minute: int, second: int = 0) -> datetime:
    return BASE + timedelta(minutes=minute, seconds=second)


def make_engine(now_minute: int = 6, threshold: int = 3,
                target: str = "webhook://alerts") -> AlertForwardEngine:
    return AlertForwardEngine(
        window_minutes=5,
        threshold=threshold,
        target=target,
        clock=lambda: at(now_minute),
    )


def add(engine: AlertForwardEngine, minute: int, second: int, line: str,
        line_number: int = 1, event_type: str = "EVEN-0002"):
    return engine.ingest_event(
        event_type_id=event_type,
        occurred_at=at(minute, second),
        original_line=line,
        source_id="app-01",
        line_number=line_number,
    )


def make_record(line: str, minute: int, index: int,
                event_type: EventTypeDef | None = None) -> EventRecord:
    return EventRecord(
        record_id=f"EVEN-{index:06d}",
        event_type=event_type or PRESET_EVENT_TYPES["error"],
        original_content=line,
        parsed_fields={"message": line},
        masked_fields={},
        enriched_fields={},
        event_time=at(minute),
        source_host="app-01",
        store_partition="20261124",
    )


class TestWindowThreshold:
    """窗口按发生时间切分，只有达到门槛的窗才生成告警。"""

    def test_five_minute_windows_split_errors(self):
        """10:00、10:03、10:05 分属两窗，各窗单独计数。"""
        engine = make_engine(now_minute=6)
        add(engine, 0, 10, "ERROR e1")
        add(engine, 3, 0, "ERROR e2")
        add(engine, 5, 0, "ERROR e3")

        first = engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        second = engine.evaluate_window("EVEN-0002@2026-11-24T10:05")

        assert first["count"] == 2
        assert first["triggered"] is False
        assert first["closed"] is True
        assert second["count"] == 1
        assert second["triggered"] is False
        assert second["closed"] is False
        assert engine.pending_alerts() == []

    def test_window_start_alignment(self):
        """窗口起点按固定长度对齐，10:05 是下一窗的第一分钟。"""
        assert window_start(at(0, 10), 5) == at(0, 0)
        assert window_start(at(4, 59), 5) == at(0, 0)
        assert window_start(at(5, 0), 5) == at(5, 0)

    def test_retransmitted_line_does_not_raise_count(self):
        """重传 10:03 原行只累计重传次数，不提高前窗计数。"""
        engine = make_engine()
        first = add(engine, 3, 0, "ERROR e2", line_number=7)
        before = engine.evaluate_window("EVEN-0002@2026-11-24T10:00")["count"]

        again = add(engine, 3, 0, "ERROR e2", line_number=7)
        after = engine.evaluate_window("EVEN-0002@2026-11-24T10:00")

        assert again.event_id == first.event_id
        assert again.retransmissions == 1
        assert after["count"] == before == 1
        assert after["retransmissions"] == 1
        assert engine.retransmission_report()[-1]["counted"] is False

    def test_three_errors_trigger_and_forward(self):
        """三条错误达门槛并转发；更正其中一条后原包仍可重算，目标收到更正。"""
        transport = InMemoryForwardTransport()
        engine = AlertForwardEngine(
            window_minutes=5, threshold=3, target="webhook://alerts",
            transport=transport, clock=lambda: at(6),
        )
        ids = [
            add(engine, 0, 10, "ERROR e1", 1).event_id,
            add(engine, 3, 0, "ERROR e2", 2).event_id,
            add(engine, 4, 30, "ERROR e3", 3).event_id,
        ]
        engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        sent = engine.dispatch()
        assert len(sent) == 1
        package = sent[0]
        assert package["kind"] == "alert"
        assert package["trigger_basis"]["count"] == 3
        assert package["trigger_basis"]["threshold"] == 3
        assert [item["event_id"] for item in package["event_identities"]] == ids

        outcome = engine.correct_event(
            ids[1], new_event_type_id="EVEN-0001", reason="原行更正为普通访问")
        assert outcome["windows"][0]["count"] == 2
        corrections = outcome["corrections"]
        assert len(corrections) == 1
        correction = corrections[0]
        assert correction["ref_alert_id"] == package["alert_id"]
        assert correction["original_package_id"] == package["package_id"]
        assert correction["state"] == "待派发"

        recomputed = engine.recompute_alert(package["alert_id"])
        assert recomputed["matches_original"] is True
        assert recomputed["count"] == 3
        assert recomputed["triggered"] is True

        assert engine.pending_dispatch_list() == [{
            "type": "correction",
            "correction_id": correction["correction_id"],
            "alert_id": package["alert_id"],
            "window_id": "EVEN-0002@2026-11-24T10:00",
            "target": "webhook://alerts",
            "package_id": correction["package_id"],
            "count": 2,
        }]
        forwarded = engine.dispatch()
        assert [item["kind"] for item in forwarded] == ["correction"]
        assert forwarded[0]["ref_alert_id"] == package["alert_id"]
        assert forwarded[0]["withdrawn_event_ids"] == [ids[1]]
        assert forwarded[0]["trigger_basis"]["below_threshold"] is True

        receipts = transport.packages()
        assert len(receipts) == 2
        assert receipts[1]["payload"]["notice"] == "撤回门槛告警"
        assert set(receipts[1]["payload"]["event_identities"][0]) >= {
            "event_id", "event_type", "occurred_at", "original_line"}

        # 原告警与更正分别核销，且都只交付一次。
        deliveries = engine.deliveries()
        assert len(deliveries) == 2
        assert {d.kind for d in deliveries} == {"alert", "correction"}
        assert engine.dispatch() == []
        assert len(transport.packages()) == 2

    def test_repeated_correction_delivers_once(self):
        """重复送来同一更正只产生一次更正交付。"""
        engine = make_engine()
        ids = [
            add(engine, 0, 10, "ERROR e1", 1).event_id,
            add(engine, 3, 0, "ERROR e2", 2).event_id,
            add(engine, 4, 30, "ERROR e3", 3).event_id,
        ]
        engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        engine.dispatch()

        first = engine.correct_event(ids[0], reason="原行更正")
        engine.dispatch()
        second = engine.correct_event(ids[0], reason="原行更正")
        engine.dispatch()

        assert [c["correction_id"] for c in first["corrections"]] == \
            [c["correction_id"] for c in second["corrections"]]
        assert second["duplicate_correction"] is True
        assert len(engine.corrections()) == 1
        assert len(engine.transport.packages()) == 2  # 1 原包 + 1 更正


class TestLateArrivalAndRoundOrder:
    """晚到事件按其发生时间回填窗口，不改变领取顺序。"""

    def test_late_event_completes_closed_window(self):
        """10:00 的窗已结束、值班员已在领取下一轮，迟到 10:04 才第一次够门槛。"""
        engine = make_engine(now_minute=6)
        add(engine, 0, 10, "ERROR e1", 1)
        add(engine, 3, 0, "ERROR e2", 2)
        add(engine, 5, 0, "ERROR e3", 3)

        # 前窗此时不达门槛，因此不在本轮领取范围内。
        first_round = engine.claim_round()
        assert first_round["alert_ids"] == []
        assert engine.dispatch(round_id=first_round["round_id"]) == []

        late = add(engine, 4, 30, "ERROR e4", 4)
        assert late.occurred_at == at(4, 30)
        assert engine.last_ingest["window_start"] == at(0, 0).isoformat()

        evaluation = engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        assert evaluation["count"] == 3
        assert evaluation["triggered"] is True
        assert evaluation["closed"] is True

        # 晚到不能把 10:05 的记录挪进前窗。
        second = engine.evaluate_window("EVEN-0002@2026-11-24T10:05")
        assert second["count"] == 1
        assert late.event_id not in second["event_ids"]

        # 本轮已经派发过，前窗告警只能进入下一轮。
        assert engine.dispatch(round_id=first_round["round_id"]) == []
        next_round = engine.claim_round()
        assert len(next_round["alert_ids"]) == 1
        packages = engine.dispatch(round_id=next_round["round_id"])
        assert len(packages) == 1
        assert packages[0]["window_id"] == "EVEN-0002@2026-11-24T10:00"
        assert packages[0]["trigger_basis"]["count"] == 3
        assert len(packages[0]["event_identities"]) == 3

    def test_concurrent_dispatch_sends_once(self):
        """并发转发同一次达到门槛的证据最多发送一次。"""
        engine = make_engine(now_minute=10)
        add(engine, 0, 10, "ERROR e1", 1)
        add(engine, 3, 0, "ERROR e2", 2)
        add(engine, 4, 30, "ERROR e3", 3)
        engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        assert len(engine.pending_dispatch_list()) == 1

        results: list[int] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            results.append(len(engine.dispatch()))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(results) == 1
        assert results.count(1) == 1
        assert len(engine.transport.packages()) == 1
        assert len(engine.deliveries()) == 1


class TestInterruptedDeliveryAndReopen:
    """目标已收到但本端未登记时，重开原告警以回执为准。"""

    def test_target_received_but_local_registration_lost(self):
        transport = InMemoryForwardTransport()
        engine = AlertForwardEngine(
            window_minutes=5, threshold=3, target="webhook://alerts",
            transport=transport, clock=lambda: at(30),
        )
        ids = [
            add(engine, 0, 10, "ERROR e1", 1).event_id,
            add(engine, 3, 0, "ERROR e2", 2).event_id,
            add(engine, 4, 30, "ERROR e3", 3).event_id,
        ]
        engine.evaluate_window("EVEN-0002@2026-11-24T10:00")

        # 包已经送达目标，但本端登记步骤中断。
        sent = engine.dispatch(acknowledge=False)
        assert len(sent) == 1
        alert = engine.alerts()[0]
        assert alert.state == "已发送待确认"
        assert len(transport.packages()) == 1

        # 恢复期间原行更正，前窗不再够门槛。
        outcome = engine.correct_event(
            ids[1], new_event_type_id="EVEN-0001", reason="原行更正")
        assert outcome["windows"][0]["count"] == 2
        assert len(outcome["corrections"]) == 1
        assert outcome["corrections"][0]["state"] == "待派发"

        # 值班员重开原告警：以目标回执核清实际送达，不重发旧包。
        reopened = engine.reopen_alert(alert.alert_id)
        assert reopened["target_received"] is True
        assert reopened["alert_state"] == ALERT_DELIVERED
        assert reopened["delivery"]["state"] == ALERT_DELIVERED
        pending = engine.pending_dispatch_list()
        assert [item["type"] for item in pending] == ["correction"]

        # 重开派发只会交付更正，旧包不会再发。
        packages = engine.dispatch()
        assert [item["kind"] for item in packages] == ["correction"]
        assert packages[0]["ref_alert_id"] == alert.alert_id
        assert packages[0]["target"] == alert.target
        receipts = transport.packages()
        assert len(receipts) == 2
        assert receipts[1]["payload"]["alert_id"] == alert.alert_id

        # 原包和更正分别核销。
        deliveries = engine.deliveries()
        assert len(deliveries) == 2
        assert {d.state for d in deliveries} == {ALERT_DELIVERED}
        assert engine.pending_dispatch_list() == []

    def test_undelivered_window_stays_available(self):
        """未交付的窗口在后续证据再次达门槛时仍能继续派发。"""
        engine = make_engine(now_minute=30)
        ids = [
            add(engine, 0, 10, "ERROR e1", 1).event_id,
            add(engine, 3, 0, "ERROR e2", 2).event_id,
            add(engine, 4, 30, "ERROR e3", 3).event_id,
        ]
        engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        alert = engine.alerts()[0]

        # 从未派发就发生更正：告警登记撤回但不删除。
        engine.correct_event(ids[0], reason="原行更正")
        assert alert.state == ALERT_WITHDRAWN
        assert engine.find_alert(alert_id=alert.alert_id) is alert
        assert engine.corrections() == []
        assert engine.pending_dispatch_list() == []

        # 该窗后续又有新证据达到门槛，未交付窗口继续可用。
        add(engine, 1, 0, "ERROR e4", 4)
        evaluation = engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        assert evaluation["count"] == 3
        assert evaluation["triggered"] is True
        pending = engine.pending_dispatch_list()
        assert len(pending) == 1
        assert pending[0]["alert_id"] == alert.alert_id
        packages = engine.dispatch()
        assert len(packages) == 1
        assert packages[0]["alert_id"] == alert.alert_id
        assert len(packages[0]["event_identities"]) == 3

    def test_reopen_builds_missing_correction(self):
        """重开时即使更正未登记，也要补出本应交给目标的更正。"""
        transport = InMemoryForwardTransport()
        engine = AlertForwardEngine(
            window_minutes=5, threshold=3, target="webhook://alerts",
            transport=transport, clock=lambda: at(30),
        )
        ids = [
            add(engine, 0, 10, "ERROR e1", 1).event_id,
            add(engine, 3, 0, "ERROR e2", 2).event_id,
            add(engine, 4, 30, "ERROR e3", 3).event_id,
        ]
        engine.evaluate_window("EVEN-0002@2026-11-24T10:00")
        engine.dispatch(acknowledge=False)
        alert = engine.alerts()[0]

        # 更正发生在恢复之前；目标已收到，但本端还没登记。
        engine.correct_event(ids[0], reason="原行更正")
        reopened = engine.reopen_alert(alert.alert_id)
        assert reopened["target_received"] is True
        assert reopened["alert_state"] == ALERT_DELIVERED
        assert [c["state"] for c in reopened["corrections"]] == ["待派发"]

        # 再次重开不重发旧包，也不会重复补更正。
        again = engine.reopen_alert(alert.alert_id)
        assert len(again["corrections"]) == len(reopened["corrections"]) == 1
        packages = engine.dispatch()
        assert [item["kind"] for item in packages] == ["correction"]
        assert len(transport.packages()) == 2
        assert engine.dispatch() == []


class TestPipelineEntry:
    """从采集管道入口核对窗口告警、重传和转发批次。"""

    def test_check_anomaly_windows_and_forward_packages(self):
        pipeline = make_pipeline()
        for minute, second, index in [(0, 10, 1), (3, 0, 2), (5, 0, 3)]:
            pipeline.check_anomaly(
                [make_record(f"ERROR line {index}", minute, index)],
                "EVEN-0002", threshold=3, now=at(6),
            )
        assert pipeline.alert_engine.pending_dispatch_list() == []

        late = make_record("ERROR late at 10:04", 4, 4)
        marked = pipeline.check_anomaly(
            [late], "EVEN-0002", threshold=3, now=at(6))
        assert marked[0].parsed_fields["anomaly_alert"] == "triggered"
        assert marked[0].parsed_fields["anomaly_window"] == "EVEN-0002@2026-11-24T10:00"

        packages = pipeline.apply_forward_rules(
            [], "webhook://alerts", threshold=3, now=at(6))
        assert len(packages) == 1
        package = packages[0]["package"]
        assert package["window_id"] == "EVEN-0002@2026-11-24T10:00"
        assert package["trigger_basis"]["rule"] == "window_threshold"
        assert package["trigger_basis"]["count"] == 3
        assert len(packages[0]["payload"]) == 3
        assert all(item["event_id"] for item in packages[0]["payload"])

        # 再次派发不会重复发送同一窗口。
        assert pipeline.apply_forward_rules(
            [], "webhook://alerts", threshold=3, now=at(6)) == []

        # 10:05 的窗没有被晚到事件污染。
        windows = {item["window_id"]: item for item in pipeline.alert_engine.window_report()}
        assert windows["EVEN-0002@2026-11-24T10:05"]["count"] == 1

    def test_reused_pipeline_engine_keeps_window_settings(self):
        """同一管道的多次调用共享窗口台账与规则。"""
        pipeline = make_pipeline()
        pipeline.check_anomaly(
            [make_record("ERROR a", 0, 1)], "EVEN-0002", threshold=3,
            window_minutes=5, target="webhook://alerts", now=at(6))
        pipeline.check_anomaly(
            [make_record("ERROR b", 1, 2)], "EVEN-0002", threshold=3,
            window_minutes=5, target="webhook://alerts", now=at(6))
        pipeline.check_anomaly(
            [make_record("ERROR c", 2, 3)], "EVEN-0002", threshold=3,
            window_minutes=5, target="webhook://alerts", now=at(6))

        assert pipeline.alert_engine.rule_for("EVEN-0002")["window_minutes"] == 5
        pending = pipeline.alert_engine.pending_dispatch_list()
        assert len(pending) == 1
        assert pending[0]["target"] == "webhook://alerts"


class TestModuleServices:
    """异常告警与转发路由两个领域服务共享同一份窗口台账。"""

    def _reset(self, transport: InMemoryForwardTransport | None = None) -> None:
        from app.core import alert_registry
        alert_registry.set_engine(AlertForwardEngine(
            window_minutes=5, threshold=3, target="webhook://alerts",
            transport=transport or InMemoryForwardTransport(), clock=lambda: at(6),
        ))

    def test_check_anomaly_then_forward_round(self):
        from app.services.anomaly_rule import AnomalyRuleService
        from app.services.forward_rule import ForwardRuleService

        self._reset()
        anomaly = AnomalyRuleService()
        forward = ForwardRuleService()
        records = [
            {"event_type": "EVEN-0002", "occurred_at": f"2026-11-24T10:0{minute}:00",
             "original_line": f"ERROR {minute}", "source_id": "app-01",
             "line_number": index}
            for index, minute in enumerate([0, 3, 5])
        ]
        result = anomaly.check_anomaly(records, event_type_id="EVEN-0002", threshold=3)
        windows = {item["window_id"]: item for item in result["windows"]}
        assert windows["EVEN-0002@2026-11-24T10:00"]["count"] == 2
        assert windows["EVEN-0002@2026-11-24T10:05"]["count"] == 1
        assert all(item["triggered"] is False for item in result["windows"])
        assert forward.pending()["items"] == []

        round_one = forward.dispatch_round()
        assert round_one["packages"] == []
        assert round_one["dispatched"] is False

    def test_forward_only_sends_triggered_window(self):
        from app.services.anomaly_rule import AnomalyRuleService
        from app.services.forward_rule import ForwardRuleService

        transport = InMemoryForwardTransport()
        self._reset(transport)
        anomaly = AnomalyRuleService()
        forward = ForwardRuleService()
        records = [
            {"event_type": "EVEN-0002", "occurred_at": "2026-11-24T10:00:10",
             "original_line": "ERROR e1", "source_id": "app-01", "line_number": 1},
            {"event_type": "EVEN-0002", "occurred_at": "2026-11-24T10:03:00",
             "original_line": "ERROR e2", "source_id": "app-01", "line_number": 2},
            {"event_type": "EVEN-0002", "occurred_at": "2026-11-24T10:04:30",
             "original_line": "ERROR e3", "source_id": "app-01", "line_number": 3},
            {"event_type": "EVEN-0002", "occurred_at": "2026-11-24T10:05:00",
             "original_line": "ERROR e4", "source_id": "app-01", "line_number": 4},
        ]
        anomaly.check_anomaly(records, event_type_id="EVEN-0002", threshold=3)
        pending = forward.pending()
        assert len(pending["alert_ids"]) == 1

        dispatched = forward.dispatch_round()
        assert dispatched["dispatched"] is True
        assert len(dispatched["packages"]) == 1
        package = dispatched["packages"][0]
        assert package["window_id"] == "EVEN-0002@2026-11-24T10:00"
        assert len(package["event_identities"]) == 3
        assert len(transport.packages()) == 1

        # 第二个窗口没有达门槛，不会因为本轮派发而被带出。
        assert forward.dispatch_round()["packages"] == []


# ---------- 运行入口（确定性测试，不依赖 pytest） ----------

if __name__ == "__main__":
    tests = {
        "window_split": TestWindowThreshold().test_five_minute_windows_split_errors,
        "window_alignment": TestWindowThreshold().test_window_start_alignment,
        "retransmit_no_count": TestWindowThreshold().test_retransmitted_line_does_not_raise_count,
        "trigger_and_correct": TestWindowThreshold().test_three_errors_trigger_and_forward,
        "repeated_correction_once": TestWindowThreshold().test_repeated_correction_delivers_once,
        "late_completes_closed_window":
            TestLateArrivalAndRoundOrder().test_late_event_completes_closed_window,
        "concurrent_dispatch_once":
            TestLateArrivalAndRoundOrder().test_concurrent_dispatch_sends_once,
        "interrupted_delivery_reopen":
            TestInterruptedDeliveryAndReopen().test_target_received_but_local_registration_lost,
        "undelivered_window_continues":
            TestInterruptedDeliveryAndReopen().test_undelivered_window_stays_available,
        "reopen_builds_correction":
            TestInterruptedDeliveryAndReopen().test_reopen_builds_missing_correction,
        "pipeline_entry": TestPipelineEntry().test_check_anomaly_windows_and_forward_packages,
        "pipeline_engine_settings": TestPipelineEntry().test_reused_pipeline_engine_keeps_window_settings,
        "service_check_anomaly": TestModuleServices().test_check_anomaly_then_forward_round,
        "service_forward_triggered_only": TestModuleServices().test_forward_only_sends_triggered_window,
    }

    passed = 0
    failed = 0
    for name, test_func in tests.items():
        try:
            test_func()
            passed += 1
            print(f"  PASS  test_alert_window: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  test_alert_window: {name}")
            traceback.print_exc()

    print(f"\ntest_alert_window: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
