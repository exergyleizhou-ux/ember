"""P4: 接口暴露(OWASP API8/API9)。

graphql-introspection · debug/swagger 暴露 · HTTP 方法篡改(TRACE/XST) · verbose 报错。
都是被动检查:看目标自己暴露了什么。
"""

import re

from .base import Detector, register

# GraphQL 常见路径
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql")

# 不该对外暴露的调试/文档路径
DEBUG_PATHS = (
    "/openapi.json", "/swagger.json", "/swagger-ui", "/api-docs",
    "/graphiql", "/actuator", "/actuator/env", "/debug",
    "/server-status", "/.env", "/.git/config",
)

# 报错正文里的栈/框架泄露特征
_STACKTRACE_MARKERS = (
    r"Traceback \(most recent call last\)",
    r'File ".*", line \d+',
    r"\bat [a-z]+\.[a-zA-Z.]+\(",      # java: at com.foo.Bar(
    r"Exception in thread",
    r"\.java:\d+\)",
    r"/usr/(local/)?lib",
    r"goroutine \d+ \[",               # go panic
)


def is_introspection_enabled(body: str) -> bool:
    """响应里出现 schema 元信息 → introspection 开着。纯函数。"""
    b = body or ""
    return "__schema" in b or '"types"' in b or '"queryType"' in b


def is_verbose_error(body: str) -> bool:
    """响应里含栈/框架泄露特征。纯函数。"""
    b = body or ""
    return any(re.search(p, b) for p in _STACKTRACE_MARKERS)


@register
class GraphqlIntrospectionDetector(Detector):
    name = "graphql-introspection"
    owasp = "API9:2023"
    severity = "medium"

    def run(self, ctx):
        print(f"\n🔍 GRAPHQL-INTROSPECTION: 探 {len(GRAPHQL_PATHS)} 个 GraphQL 路径")
        for path in GRAPHQL_PATHS:
            status, body, _ = ctx._raw_get(
                path, method="POST",
                headers={"Content-Type": "application/json"},
                body={"query": "{__schema{types{name}}}"})
            ctx.stats["total"] += 1
            if status and 200 <= status < 300 and is_introspection_enabled(body):
                ctx._add(self.severity, self.name, path, "POST",
                         "GraphQL introspection 开启,schema 对外暴露")
            else:
                ctx.stats["passed"] += 1


@register
class DebugExposureDetector(Detector):
    name = "debug-exposure"
    owasp = "API8:2023"
    severity = "medium"

    def run(self, ctx):
        print(f"\n🔍 DEBUG-EXPOSURE: 探 {len(DEBUG_PATHS)} 个调试/文档路径")
        for path in DEBUG_PATHS:
            status, body, _ = ctx._raw_get(path)
            ctx.stats["total"] += 1
            if status and 200 <= status < 300 and body.strip():
                ctx._add(self.severity, self.name, path, "GET",
                         "调试/文档端点对外可访问", evidence=body[:120])
            else:
                ctx.stats["passed"] += 1


@register
class HttpMethodTamperingDetector(Detector):
    name = "http-method"
    owasp = "API8:2023"
    severity = "low"

    def run(self, ctx):
        print("\n🔍 HTTP-METHOD: TRACE 方法检测(XST)")
        status, body, _ = ctx._raw_get("/", method="TRACE")
        ctx.stats["total"] += 1
        # TRACE 被接受并回显请求 → 跨站追踪(XST)风险
        if status and 200 <= status < 300 and ("TRACE" in (body or "")):
            ctx._add(self.severity, self.name, "/", "TRACE",
                     "TRACE 方法被接受并回显请求(XST 风险)")
        else:
            ctx.stats["passed"] += 1


@register
class VerboseErrorDetector(Detector):
    name = "verbose-errors"
    owasp = "API8:2023"
    severity = "low"

    def run(self, ctx):
        probes = [ep for ep in ctx.public if ep["method"] == "GET"] or [{"path": "/", "method": "GET"}]
        print(f"\n🔍 VERBOSE-ERRORS: 打 {len(probes)} 个端点(畸形输入触发报错)")
        for ep in probes:
            base = ctx._resolve(ep["path"])
            sep = "&" if "?" in base else "?"
            status, body, _ = ctx._raw_get(f"{base}{sep}id[]=1&n=%ff%00")
            ctx.stats["total"] += 1
            if is_verbose_error(body):
                ctx._add(self.severity, self.name, base, "GET",
                         "报错响应泄露栈/框架信息", evidence=body[:120])
            else:
                ctx.stats["passed"] += 1
