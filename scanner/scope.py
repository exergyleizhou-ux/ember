#!/usr/bin/env python3
"""
授权护栏 — 在任何扫描动作之前,强制目标落在显式声明的授权范围内。

为什么需要它:
  未授权扫描在多数司法辖区都是违法的。一个生产级安全工具必须从结构上
  阻止"手滑打错目标",而不是靠使用者自觉。本机(localhost/回环)视为
  自测,始终放行;其它目标必须出现在 --scope allowlist 里。

纯函数,无副作用,便于测试。
"""

from urllib.parse import urlparse

# 回环/本机地址:自测场景,始终允许
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class UnauthorizedTargetError(Exception):
    """目标不在授权范围内。"""


def target_host(target: str) -> str:
    """从 URL 或裸主机串里取出主机名(小写,去端口)。"""
    if not target:
        return ""
    parsed = urlparse(target if "://" in target else "//" + target)
    return (parsed.hostname or "").lower()


def is_authorized(target: str, allowlist) -> bool:
    """目标主机是否被授权:本机恒真;否则需精确匹配或为某授权域的子域。"""
    host = target_host(target)
    if not host:
        return False
    if host in LOCAL_HOSTS:
        return True
    for allowed in allowlist:
        a = (allowed or "").strip().lower()
        if not a:
            continue
        if host == a or host.endswith("." + a):
            return True
    return False


def require_authorized(target: str, allowlist) -> None:
    """未授权则抛 UnauthorizedTargetError,带可操作的提示。"""
    if is_authorized(target, allowlist):
        return
    allowed = sorted({(a or "").strip().lower() for a in allowlist if (a or "").strip()})
    raise UnauthorizedTargetError(
        f"目标 {target_host(target)!r} 不在授权范围内。\n"
        f"扫描非本机目标必须用 --scope 显式声明授权(逗号分隔的主机/域名),"
        f"并确保你拥有书面授权。\n"
        f"当前授权范围: {allowed or '(空)'}"
    )


def parse_scope(raw: str):
    """把 '--scope a.com, b.com' 解析成列表。"""
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]
