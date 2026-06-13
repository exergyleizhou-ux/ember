"""
越狱输入守卫(守侧 / 防御原语)。

作用:对**进入你自己 LLM 应用的输入**做一道前置筛查,识别常见的越狱框架措辞
(ATLAS AML.T0054)。它**检测针对你应用的越狱尝试**,不生成、不优化任何越狱。

与 injection_guard 的分工:
  - injection_guard:针对"覆盖系统指令"的直接注入(T0051.000)
  - jailbreak_guard :针对"绕过 alignment / 扮演无限制角色"的越狱框架(T0054)
两者互补,都是纵深防御的外层信号。

定位(诚实,务必读):
  - 透明、基于签名的启发式。**攻击者改写措辞即可绕过**——签名永远落在新越狱后面。
  - 必然有误报/漏报;**不是独立防御**,不能当"过了就安全"。
  - 真正的边界是 dual-LLM + taint(doc 01/02):让不可信输入结构上无法驱动工具,
    那样即便越狱成功,也调不动有副作用的东西。
  - 本文件**只识别**已知越狱框架,**不含任何可用的越狱 payload**。

参考:OWASP LLM01:2025;ATLAS AML.T0054;JailbreakBench(评测基线,非本仓内置)。
"""

import re
from typing import List, Tuple

# 已知越狱"框架"措辞签名(公开、防御用):识别意图,不是可用 payload。
JAILBREAK_SIGNATURES: List[Tuple[str, str]] = [
    (r"\bdo anything now\b|\bDAN\b", "DAN 类无限制人格"),
    (r"\b(no|without) (restrictions?|limits?|filters?|guidelines?|rules?)\b", "声称无限制"),
    (r"\byou (can|are able to) (now )?(do|say) anything\b", "解除约束话术"),
    (r"\b(ignore|bypass|disable|turn off)\b.{0,30}\b(safety|alignment|guardrail|moderation|content policy)\b", "明示关闭安全"),
    (r"\b(developer|god|jailbreak|unrestricted|uncensored|root) mode\b", "伪特权/越狱模式"),
    (r"\bpretend (you|to be)\b.{0,40}\b(no|without|free of)\b.{0,20}\b(rules?|restrictions?|filter)", "扮演无约束角色"),
    (r"\bhypothetical(ly)?\b.{0,40}\b(no|ignore|without)\b.{0,20}\b(rules?|restrictions?|consequences?)", "假设外壳绕过"),
    (r"\broleplay\b.{0,40}\b(evil|villain|hacker|amoral|unfiltered)\b", "恶意角色扮演框架"),
    (r"\bopposite (day|mode)\b|\banti-?(gpt|ai)\b", "反转人格框架"),
    (r"\bfor (educational|research) purposes only\b.{0,40}\b(illegal|harmful|weapon|exploit)\b", "学术外壳 + 有害目标"),
    (r"\byou are (not|no longer) (an? )?(ai|assistant|bound)", "否认 AI 身份"),
    (r"\bstay in character\b.{0,30}\b(no matter what|always)\b", "锁定越狱人格"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), why) for p, why in JAILBREAK_SIGNATURES]


def matches(text: str) -> List[str]:
    if not text:
        return []
    return [why for rx, why in _COMPILED if rx.search(text)]


def jailbreak_score(text: str) -> float:
    """命中越狱框架签名越多分越高,归一 0..1。相对信号,不是概率。"""
    if not text:
        return 0.0
    return min(1.0, len(matches(text)) / 3.0)


def is_likely_jailbreak(text: str, threshold: float = 0.33) -> bool:
    """是否疑似越狱框架。默认命中 1 条签名即标记。

    用法(应用入口,与 dual-LLM 配合):
        if is_likely_jailbreak(user_input):
            log_and_route_to_review(user_input)   # 记录 + 降级/人工,别静默放行
    记住:这是外层信号,真正的边界是 dual-LLM + taint。
    """
    return jailbreak_score(text) >= threshold
