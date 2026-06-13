"""
查询预算守卫(守侧 / 运行时滥用监测原语)。

作用:在**进程内**按身份(用户/API key/IP)做滑动窗口限额,挡住模型提取
(海量查询提炼模型,ATLAS AML.T0024.002)、成本耗尽(AML.T0034)、推理 DoS
(AML.T0029)。零依赖,不需要 Prometheus;要接 SIEM 时把 stats() 的数读出去即可。

时钟用依赖注入(time_fn),便于测试与确定性。
"""

import time
from collections import defaultdict, deque
from typing import Callable, Optional


class BudgetGuard:
    def __init__(self, max_calls: int, window_seconds: float,
                 max_cost: Optional[float] = None,
                 time_fn: Callable[[], float] = time.monotonic):
        self.max_calls = max_calls
        self.window = window_seconds
        self.max_cost = max_cost
        self._time_fn = time_fn
        self._events = defaultdict(deque)   # identity -> deque[(ts, cost)]

    def _evict(self, identity):
        now = self._time_fn()
        dq = self._events[identity]
        while dq and dq[0][0] < now - self.window:
            dq.popleft()

    def record(self, identity: str, cost: float = 1.0):
        self._evict(identity)
        self._events[identity].append((self._time_fn(), cost))

    def is_over_budget(self, identity: str) -> bool:
        self._evict(identity)
        dq = self._events[identity]
        if len(dq) > self.max_calls:
            return True
        if self.max_cost is not None and sum(c for _, c in dq) > self.max_cost:
            return True
        return False

    def check(self, identity: str, cost: float = 1.0) -> bool:
        """记录本次调用并返回是否已越预算(True = 滥用信号,应限流/告警)。"""
        self.record(identity, cost)
        return self.is_over_budget(identity)

    def active_identities(self) -> int:
        """当前窗口内仍有事件的去重身份数(供指标导出)。"""
        count = 0
        for ident in list(self._events.keys()):
            self._evict(ident)
            if self._events[ident]:
                count += 1
        return count

    def stats(self, identity: str) -> dict:
        """当前窗口内该身份的用量(供导出到 SIEM/Prometheus)。"""
        self._evict(identity)
        dq = self._events[identity]
        return {
            "identity": identity,
            "calls": len(dq),
            "cost": sum(c for _, c in dq),
            "max_calls": self.max_calls,
            "max_cost": self.max_cost,
            "window_seconds": self.window,
        }
