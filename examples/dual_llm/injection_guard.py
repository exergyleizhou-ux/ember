"""
透明启发式注入输入守卫(守侧 / 防御原语)。

作用:对**进入你自己 LLM 应用的输入**做一道前置筛查,标记常见的直接注入措辞
(ATLAS AML.T0051.000)。这是给防守方用的"WAF 规则"式信号 —— 它**检测针对你
应用的注入尝试**,不生成任何注入。

定位(诚实):
  - 这是**透明的、基于签名的启发式**,不是 ML 分类器,不追求 SOTA 精度。
  - 必然有误报/漏报。攻击者改写措辞就能绕过签名。
  - **不是独立防御**。真正的结构性防御是 dual-LLM + taint(doc 01/02)。
    本守卫只是纵深防御里最外面、最便宜的一层,用来挡掉低成本的明文注入。
  - 不要把它当成"过了就安全"。它只降低噪声,不改变信任边界。

参考:OWASP LLM01:2025;ATLAS AML.T0051.000;Lakera PINT(评测基线)。
"""

import re
from typing import List, Tuple

# 已知的直接注入/越权措辞签名(公开、防御用)。每条是 (正则, 说明)。
INJECTION_SIGNATURES: List[Tuple[str, str]] = [
    (r"\bignore (the |all |your )?(previous|above|prior|earlier|preceding)\b", "覆盖既有指令"),
    (r"\bdisregard (the |all |your )?(previous|above|prior|instructions)\b", "覆盖既有指令"),
    (r"\bforget (everything|all|the above|previous)\b", "覆盖既有指令"),
    (r"\b(reveal|print|show|repeat|output|leak)\b.{0,30}\b(system )?(prompt|instructions?)\b", "套取系统提示"),
    (r"\byou are (now |no longer )", "角色重置"),
    (r"\bact as\b.{0,20}\b(dan|developer mode|jailbroken|unrestricted)\b", "越权角色扮演"),
    (r"\bpretend (to be|you are)\b", "角色伪装"),
    (r"\b(developer|god|admin|root) mode\b", "伪特权模式"),
    (r"\bdo anything now\b|\bDAN\b", "DAN 类越狱措辞"),
    (r"\bnew (instructions?|rules?|task)\b\s*[:：]", "注入新指令块"),
    (r"</?(system|instruction|prompt)>", "伪造系统标签"),
    (r"\bbypass\b.{0,20}\b(filter|guardrail|safety|restriction)\b", "明示绕过防护"),
    (r"\bend of (prompt|instructions?)\b", "伪造提示边界"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), why) for p, why in INJECTION_SIGNATURES]


def matches(text: str) -> List[str]:
    """返回命中的签名说明列表(可能为空)。"""
    if not text:
        return []
    return [why for rx, why in _COMPILED if rx.search(text)]


def injection_score(text: str) -> float:
    """命中签名越多分越高,归一到 0..1。仅作相对信号,不是概率。"""
    if not text:
        return 0.0
    hits = len(matches(text))
    # 1 个命中已可疑;3+ 个基本确定
    return min(1.0, hits / 3.0)


def is_likely_injection(text: str, threshold: float = 0.33) -> bool:
    """是否疑似直接注入。默认阈值 = 命中 1 条签名即标记(score=1/3≈0.333)。

    用法(在你的应用入口):
        if is_likely_injection(user_input):
            log_and_route_to_review(user_input)   # 不要直接拒绝用户,记录 + 走人工/降级
    记住:这只是纵深防御最外层,真正的边界是 dual-LLM + taint。
    """
    return injection_score(text) >= threshold
