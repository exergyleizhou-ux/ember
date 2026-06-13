"""P3: open redirect + Host 头注入(OWASP API7 / 配置)。

被动:发一个指向攻击者域的输入,看响应是否把它回吐到 Location 或正文。
"""

from urllib.parse import quote, urlparse

from .base import Detector, register

EVIL_HOST = "evil.example"
EVIL_URL = f"https://{EVIL_HOST}/x"

# 常见重定向参数名
REDIRECT_PARAMS = ("next", "url", "redirect", "return", "returnUrl", "dest", "continue")


def location_host(location: str) -> str:
    return (urlparse(location or "").hostname or "").lower()


def is_open_redirect(evil_host: str, location: str) -> bool:
    """Location 指向攻击者域即为 open redirect。纯函数。"""
    return location_host(location) == (evil_host or "").lower()


def reflects_host(evil_host: str, body: str, location: str) -> bool:
    """伪造的 Host 出现在正文或 Location 里 → Host 头注入(缓存投毒/重置投毒)。"""
    eh = (evil_host or "").lower()
    if not eh:
        return False
    return eh in (body or "").lower() or location_host(location) == eh


@register
class OpenRedirectDetector(Detector):
    name = "open-redirect"
    owasp = "API7:2023"
    severity = "medium"

    def run(self, ctx):
        gets = [ep for ep in ctx.public if ep["method"] == "GET"]
        print(f"\n🔍 OPEN-REDIRECT: 打 {len(gets)} 个公共 GET 端点")
        for ep in gets:
            base = ctx._resolve(ep["path"])
            for param in REDIRECT_PARAMS:
                sep = "&" if "?" in base else "?"
                path = f"{base}{sep}{param}={quote(EVIL_URL, safe='')}"
                status, _, headers = ctx._raw_get(path)
                ctx.stats["total"] += 1
                loc = headers.get("Location") or headers.get("location") or ""
                if 300 <= status < 400 and is_open_redirect(EVIL_HOST, loc):
                    ctx._add(self.severity, self.name, base, "GET",
                             f"参数 {param} 可重定向到任意外部域", evidence=f"Location: {loc}")
                else:
                    ctx.stats["passed"] += 1


@register
class HostHeaderInjectionDetector(Detector):
    name = "host-header"
    owasp = "API8:2023"
    severity = "medium"

    def run(self, ctx):
        probes = [ep for ep in ctx.public if ep["method"] == "GET"] or [{"path": "/", "method": "GET"}]
        print(f"\n🔍 HOST-HEADER: 打 {len(probes)} 个端点(伪造 Host)")
        for ep in probes:
            p = ctx._resolve(ep["path"])
            status, body, headers = ctx._raw_get(p, headers={"Host": EVIL_HOST})
            ctx.stats["total"] += 1
            if status == 0:
                ctx._add("medium", self.name, p, "GET", "连接失败 (目标不可达?)")
                ctx.stats["errors"] += 1
                continue
            loc = headers.get("Location") or headers.get("location") or ""
            if reflects_host(EVIL_HOST, body, loc):
                ctx._add(self.severity, self.name, p, "GET",
                         "伪造的 Host 头被反射(缓存投毒 / 密码重置投毒风险)",
                         evidence=f"Host: {EVIL_HOST}")
            else:
                ctx.stats["passed"] += 1
