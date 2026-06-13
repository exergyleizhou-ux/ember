"""
多 agent 运行时审计(守侧 / 运行时拦截)。

静态检测器 `llm-multi-agent-message-audit` 在源码层找"未净化数据跨 agent"的面;
本模块是它的**运行时补充**:在 agent 间消息真正传递时拦一道,挡 prompt 注入蠕虫
(Morris-II 类:一个 agent 把注入 payload 传给下一个 agent)。

纯组合,复用已有原语,不新增检测逻辑:
  - taint:payload 是否 Tainted(未净化数据跨边界)
  - injection_guard / jailbreak_guard:payload 文本是否含注入/越狱框架

policy:
  - "block":命中即抛 AgentMessageBlocked(消息不投递)
  - "warn" :命中记事件、仍投递(默认)
  - "off"  :不审计

审计事件可喂给 budget_metrics 或任意 SIEM(on_event 回调)。
"""

import injection_guard
import jailbreak_guard
from taint import is_tainted


class AgentMessageBlocked(Exception):
    """被审计策略拦下的跨 agent 消息。"""


def audit_message(payload, policy: str = "warn", on_event=None) -> dict:
    """审计一条跨 agent payload,返回结构化事件;policy=block 命中则抛。"""
    reasons = []
    if is_tainted(payload):
        reasons.append({"kind": "taint", "detail": f"未净化数据跨 agent 边界 (source={payload.source})"})
    text = str(payload)
    inj = injection_guard.matches(text)
    if inj:
        reasons.append({"kind": "injection", "detail": inj})
    jb = jailbreak_guard.matches(text)
    if jb:
        reasons.append({"kind": "jailbreak", "detail": jb})

    event = {"flagged": bool(reasons), "reasons": reasons, "preview": text[:80]}
    if on_event is not None:
        on_event(event)
    if reasons and policy == "block":
        raise AgentMessageBlocked(f"跨 agent 消息被拦: {[r['kind'] for r in reasons]}")
    return event


class AuditedAgentBus:
    """带审计的 agent 消息总线。send() 前先审计;deliver_fn 实际投递。"""

    def __init__(self, policy: str = "warn", on_event=None, deliver_fn=None):
        self.policy = policy
        self.on_event = on_event
        self.deliver_fn = deliver_fn
        self.events = []

    def send(self, sender: str, receiver: str, payload):
        if self.policy == "off":
            event = {"flagged": False, "reasons": [], "preview": str(payload)[:80]}
        else:
            event = audit_message(payload, self.policy, self.on_event)
        event.update(sender=sender, receiver=receiver)
        self.events.append(event)
        # 未被拦(block 命中时上面已抛)→ 投递
        if self.deliver_fn is not None:
            return self.deliver_fn(sender, receiver, payload)
        return event
