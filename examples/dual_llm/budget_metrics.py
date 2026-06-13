"""
查询预算的 Prometheus 导出(守侧 / 运行时可观测)。

把 BudgetGuard 的用量导出成 Prometheus 指标,供告警/看板消费滥用信号
(模型提取、成本耗尽、推理 DoS)。

设计决定:
  - **聚合指标,不按身份打 label** —— per-identity label 会基数爆炸(Prometheus 反模式)。
    身份级细节走日志/审计事件,不进指标。
  - `prometheus_client` 是**可选依赖**:没装则降级成 no-op,不影响 BudgetGuard 本身。
  - registry 可注入,便于测试与多实例隔离。

指标:
  ember_llm_queries_total       Counter  总查询数
  ember_llm_cost_total          Counter  总成本
  ember_llm_over_budget_total   Counter  越预算次数(check() 触发)
  ember_llm_active_identities   Gauge    当前窗口活跃身份数
"""


def _make_metrics(registry=None, enabled: bool = True):
    """构造指标;prometheus_client 不可用或 enabled=False 时返回 None(no-op)。"""
    if not enabled:
        return None
    try:
        from prometheus_client import Counter, Gauge
    except ImportError:
        return None
    kw = {} if registry is None else {"registry": registry}
    return {
        "queries": Counter("ember_llm_queries_total", "LLM 查询总数", **kw),
        "cost": Counter("ember_llm_cost_total", "LLM 查询总成本", **kw),
        "over_budget": Counter("ember_llm_over_budget_total", "越预算次数", **kw),
        "active": Gauge("ember_llm_active_identities", "窗口内活跃身份数", **kw),
    }


class MeteredBudgetGuard:
    """包装 BudgetGuard,在 check() 时打 Prometheus 点。接口与 BudgetGuard 一致。"""

    def __init__(self, guard, registry=None, enabled: bool = True):
        self.guard = guard
        self._m = _make_metrics(registry, enabled)

    @property
    def metrics_enabled(self) -> bool:
        return self._m is not None

    def check(self, identity: str, cost: float = 1.0) -> bool:
        over = self.guard.check(identity, cost)
        if self._m:
            self._m["queries"].inc()
            self._m["cost"].inc(cost)
            if over:
                self._m["over_budget"].inc()
            self._m["active"].set(self.guard.active_identities())
        return over

    # 透传只读接口
    def is_over_budget(self, identity: str) -> bool:
        return self.guard.is_over_budget(identity)

    def stats(self, identity: str) -> dict:
        return self.guard.stats(identity)


def serve_metrics(port: int = 9108):
    """起一个 /metrics HTTP 端点(示例;需要 prometheus_client)。"""
    from prometheus_client import start_http_server
    start_http_server(port)
    print(f"Prometheus /metrics 已在 :{port}")
