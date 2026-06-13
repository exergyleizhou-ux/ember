"""守侧主动注入检测器家族(mode=http)。

补齐守侧此前的盲区:传统 Web 注入类只有 payloads/engine 的探测,没有
dual-tested 的注册检测器。这里把 SQLi / XSS / 命令注入 / SSTI / 路径遍历
做成正式检测器,对端点参数发探测、分析响应,双向钉死。

判定都是被动分析"目标自己的响应"(报错反射 / 原样回显 / 模板求值 / 时间延迟 /
文件内容泄露),纯函数便于单测。探测经查询参数(GET),POST/body 注入留待后续。
"""

import re
import time
from urllib.parse import quote

from .base import Detector, register

# ── 纯分析函数 ──
_SQL_ERROR_RX = [re.compile(p, re.I) for p in [
    r"SQL syntax", r"mysql_fetch", r"ORA-\d{4,5}", r"PostgreSQL.*(ERROR|error)",
    r"Unclosed quotation mark", r"quoted string not properly terminated",
    r"ODBC.*Driver", r"SQLSTATE", r"syntax error at or near", r"SQLite",
]]

# 求值 canary:{{1337*1337}} / ${1337*1337} → 1787569(高辨识度,极少巧合)
SSTI_CANARY_IN = "{{1337*1337}}"
SSTI_CANARY_IN2 = "${1337*1337}"
SSTI_CANARY_OUT = "1787569"

# XSS 标记:回显时若未编码则原样出现 <ember-xss>;编码则成 &lt;ember-xss&gt;
XSS_MARKER = "<ember-xss-9d3f>"


def new_sql_error(safe_body: str, injected_body: str) -> bool:
    """注入响应里新增了 SQL 报错(基线没有)→ 报错型 SQLi。"""
    return any(rx.search(injected_body or "") and not rx.search(safe_body or "")
               for rx in _SQL_ERROR_RX)


def reflected_unencoded(marker: str, body: str) -> bool:
    """标记原样(未 HTML 编码)出现在响应里 → 反射型 XSS。"""
    return marker in (body or "")


def ssti_evaluated(body: str) -> bool:
    """canary 被服务端模板求值(出现 1787569)→ SSTI。"""
    return SSTI_CANARY_OUT in (body or "")


def passwd_leaked(body: str) -> bool:
    """响应里出现 /etc/passwd 特征行 → 路径遍历读到了文件。"""
    return bool(re.search(r"root:.*:0:0:", body or ""))


# ── 检测器基类 ──
class _GetProbeDetector(Detector):
    owasp = "A03:2021"
    mode = "http"
    param = "q"

    def _endpoints(self, ctx):
        # 探测 public + jwt 里的 GET 端点
        return [e for e in (ctx.public + ctx.jwt) if e.get("method", "GET") == "GET"]

    def _probe(self, ctx, base, payload):
        sep = "&" if "?" in base else "?"
        path = f"{base}{sep}{self.param}={quote(payload, safe='')}"
        t0 = time.monotonic()
        status, body, _ = ctx._raw_get(path, follow_redirects=True)
        return status, body, time.monotonic() - t0


@register
class SqliDetector(_GetProbeDetector):
    name = "sqli-active"
    severity = "critical"

    def run(self, ctx):
        eps = self._endpoints(ctx)
        print(f"\n🔍 SQLI-ACTIVE: 打 {len(eps)} 个 GET 端点(报错 + 时间盲注)")
        for ep in eps:
            base = ctx._resolve(ep["path"])
            _, safe_body, safe_t = self._probe(ctx, base, "ember-benign-7")
            ctx.stats["total"] += 1
            # 报错型
            _, err_body, _ = self._probe(ctx, base, "'")
            if new_sql_error(safe_body, err_body):
                ctx._add("critical", self.name, base, "GET", "报错型 SQLi:注入单引号触发 SQL 报错",
                         evidence=err_body[:160])
                continue
            # 时间盲注
            _, _, slow_t = self._probe(ctx, base, "1' AND SLEEP(3)-- -")
            if slow_t - safe_t > 1.5:
                ctx._add("critical", self.name, base, "GET",
                         f"时间盲注 SQLi:SLEEP 探测延迟 {slow_t - safe_t:.1f}s", evidence="1' AND SLEEP(3)--")
                continue
            ctx.stats["passed"] += 1


@register
class XssReflectedDetector(_GetProbeDetector):
    name = "xss-reflected"
    severity = "high"

    def run(self, ctx):
        eps = self._endpoints(ctx)
        print(f"\n🔍 XSS-REFLECTED: 打 {len(eps)} 个 GET 端点(标记回显)")
        for ep in eps:
            base = ctx._resolve(ep["path"])
            ctx.stats["total"] += 1
            _, body, _ = self._probe(ctx, base, XSS_MARKER)
            if reflected_unencoded(XSS_MARKER, body):
                ctx._add("high", self.name, base, "GET", "反射型 XSS:标记未编码原样回显",
                         evidence=XSS_MARKER)
            else:
                ctx.stats["passed"] += 1


@register
class CommandInjectionDetector(_GetProbeDetector):
    name = "command-injection"
    severity = "critical"

    def run(self, ctx):
        eps = self._endpoints(ctx)
        print(f"\n🔍 COMMAND-INJECTION: 打 {len(eps)} 个 GET 端点(时间盲注)")
        for ep in eps:
            base = ctx._resolve(ep["path"])
            _, _, safe_t = self._probe(ctx, base, "ember-benign-7")
            ctx.stats["total"] += 1
            hit = False
            for payload in ("; sleep 3", "| sleep 3", "& sleep 3"):
                _, _, slow_t = self._probe(ctx, base, payload)
                if slow_t - safe_t > 1.5:
                    ctx._add("critical", self.name, base, "GET",
                             f"命令注入(时间盲注):{payload!r} 延迟 {slow_t - safe_t:.1f}s",
                             evidence=payload)
                    hit = True
                    break
            if not hit:
                ctx.stats["passed"] += 1


@register
class SstiDetector(_GetProbeDetector):
    name = "ssti"
    severity = "critical"

    def run(self, ctx):
        eps = self._endpoints(ctx)
        print(f"\n🔍 SSTI: 打 {len(eps)} 个 GET 端点(模板求值 canary)")
        for ep in eps:
            base = ctx._resolve(ep["path"])
            ctx.stats["total"] += 1
            hit = False
            for payload in (SSTI_CANARY_IN, SSTI_CANARY_IN2):
                _, body, _ = self._probe(ctx, base, payload)
                if ssti_evaluated(body):
                    ctx._add("critical", self.name, base, "GET",
                             f"SSTI:模板求值 {payload} → {SSTI_CANARY_OUT}", evidence=payload)
                    hit = True
                    break
            if not hit:
                ctx.stats["passed"] += 1


@register
class PathTraversalDetector(_GetProbeDetector):
    name = "path-traversal"
    owasp = "A01:2021"
    severity = "high"

    def run(self, ctx):
        eps = self._endpoints(ctx)
        print(f"\n🔍 PATH-TRAVERSAL: 打 {len(eps)} 个 GET 端点(/etc/passwd)")
        for ep in eps:
            base = ctx._resolve(ep["path"])
            ctx.stats["total"] += 1
            hit = False
            for payload in ("../../../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"):
                _, body, _ = self._probe(ctx, base, payload)
                if passwd_leaked(body):
                    ctx._add("high", self.name, base, "GET", "路径遍历:读到 /etc/passwd 内容",
                             evidence=payload)
                    hit = True
                    break
            if not hit:
                ctx.stats["passed"] += 1
