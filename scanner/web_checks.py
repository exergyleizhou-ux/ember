#!/usr/bin/env python3
"""
守侧被动 Web 安全检查 —— 安全响应头缺失 + CORS 配置。
纯函数,只分析"目标自己返回的响应",不发任何攻击 payload,便于测试。
"""

from typing import Dict, List, Optional, Tuple

# 期望出现的安全响应头 → (说明, severity)
SECURITY_HEADERS: Dict[str, Tuple[str, str]] = {
    "strict-transport-security": ("缺少 HSTS,可被 SSL 剥离", "medium"),
    "content-security-policy": ("缺少 CSP,XSS 缓解不足", "medium"),
    "x-content-type-options": ("缺少 X-Content-Type-Options,存在 MIME 嗅探", "low"),
    "x-frame-options": ("缺少 X-Frame-Options/frame-ancestors,可被点击劫持", "low"),
}


def _lower_keys(headers: Dict[str, str]) -> Dict[str, str]:
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def missing_security_headers(headers: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """返回缺失的安全头列表: [(header_name, 说明, severity), ...]。"""
    present = _lower_keys(headers)
    # CSP 与 X-Frame-Options 二选一可缓解点击劫持:有 CSP frame-ancestors 即视为已覆盖
    csp = present.get("content-security-policy", "")
    out = []
    for name, (desc, sev) in SECURITY_HEADERS.items():
        if name in present:
            continue
        if name == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue
        out.append((name, desc, sev))
    return out


def analyze_cors(sent_origin: str, headers: Dict[str, str]) -> Optional[Tuple[str, str]]:
    """分析 CORS 响应,返回 (说明, severity) 或 None(无问题)。

    sent_origin: 请求时发送的 Origin 头(通常是一个攻击者控制的域)。
    判定:
      - ACAO 原样回显任意 Origin  → 高危(任意站点可读响应)
      - ACAO=* 且 允许携带凭证     → 高危(规范上非法,但部分栈会放行)
    """
    h = _lower_keys(headers)
    acao = (h.get("access-control-allow-origin") or "").strip()
    acac = (h.get("access-control-allow-credentials") or "").strip().lower()

    if acao == "*" and acac == "true":
        return ("CORS: ACAO=* 且 Allow-Credentials=true(任意站点可携凭证读响应)", "high")
    if sent_origin and acao == sent_origin:
        sev = "high" if acac == "true" else "medium"
        return (f"CORS: 原样回显任意 Origin {sent_origin!r}"
                f"{'(且允许凭证)' if acac == 'true' else ''}", sev)
    return None
