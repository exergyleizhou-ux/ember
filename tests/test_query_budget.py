"""query_budget.py 单元测试 —— 进程内查询预算守卫(滑动窗口,确定性假时钟)。"""

import sys
from pathlib import Path

DUAL = Path(__file__).resolve().parent.parent / "examples" / "dual_llm"
sys.path.insert(0, str(DUAL))

from query_budget import BudgetGuard  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_under_budget_ok():
    clk = FakeClock()
    g = BudgetGuard(max_calls=3, window_seconds=10, time_fn=clk)
    assert g.check("alice") is False
    assert g.check("alice") is False
    assert g.check("alice") is False  # 第 3 次仍在限内(> max 才算超)


def test_over_call_budget_flagged():
    clk = FakeClock()
    g = BudgetGuard(max_calls=3, window_seconds=10, time_fn=clk)
    for _ in range(3):
        g.check("bob")
    assert g.check("bob") is True  # 第 4 次越界


def test_window_eviction_resets():
    clk = FakeClock()
    g = BudgetGuard(max_calls=2, window_seconds=10, time_fn=clk)
    g.check("c")
    g.check("c")
    assert g.is_over_budget("c") is False
    g.check("c")
    assert g.is_over_budget("c") is True
    clk.t = 100  # 窗口滑过,旧事件被驱逐
    assert g.is_over_budget("c") is False


def test_cost_budget():
    clk = FakeClock()
    g = BudgetGuard(max_calls=1000, window_seconds=60, max_cost=10.0, time_fn=clk)
    assert g.check("d", cost=6) is False
    assert g.check("d", cost=6) is True  # 累计 12 > 10


def test_identities_isolated():
    clk = FakeClock()
    g = BudgetGuard(max_calls=1, window_seconds=10, time_fn=clk)
    g.check("x")
    g.check("x")
    assert g.is_over_budget("x") is True
    assert g.is_over_budget("y") is False  # 互不影响


def test_stats():
    clk = FakeClock()
    g = BudgetGuard(max_calls=5, window_seconds=10, max_cost=20, time_fn=clk)
    g.check("z", cost=3)
    g.check("z", cost=2)
    s = g.stats("z")
    assert s["calls"] == 2 and s["cost"] == 5 and s["max_calls"] == 5
