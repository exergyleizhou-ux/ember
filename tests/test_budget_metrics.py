"""
budget_metrics.py 测试。
metrics 路径需 prometheus_client(importorskip);no-op 降级路径无条件可测。
"""

import sys
from pathlib import Path

import pytest

DUAL = Path(__file__).resolve().parent.parent / "examples" / "dual_llm"
sys.path.insert(0, str(DUAL))

from budget_metrics import MeteredBudgetGuard  # noqa: E402
from query_budget import BudgetGuard  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


# ── no-op 降级路径(无条件)──
def test_works_without_metrics():
    g = MeteredBudgetGuard(BudgetGuard(max_calls=2, window_seconds=10, time_fn=FakeClock()),
                           enabled=False)
    assert g.metrics_enabled is False
    # 即使指标关闭,预算逻辑照常
    assert g.check("u") is False
    assert g.check("u") is False
    assert g.check("u") is True


# ── prometheus 路径 ──
def _metric_value(registry, name):
    return registry.get_sample_value(name)


def test_counters_increment_with_prometheus():
    prom = pytest.importorskip("prometheus_client")
    reg = prom.CollectorRegistry()
    g = MeteredBudgetGuard(BudgetGuard(max_calls=2, window_seconds=10, time_fn=FakeClock()),
                           registry=reg)
    assert g.metrics_enabled is True
    g.check("u", cost=2)
    g.check("u", cost=2)
    g.check("u", cost=2)  # 第 3 次越界
    assert _metric_value(reg, "ember_llm_queries_total") == 3
    assert _metric_value(reg, "ember_llm_cost_total") == 6
    assert _metric_value(reg, "ember_llm_over_budget_total") == 1
    assert _metric_value(reg, "ember_llm_active_identities") == 1
