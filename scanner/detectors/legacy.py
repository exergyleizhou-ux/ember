"""P0: 把现有 7 项检查迁进注册表(行为保持)。

auth-bypass / ops-escalate / rate-bypass / idor / info-leak / sec-headers / cors
逻辑与原 Scanner.scan_* 一致,只是改为通过 ctx 调用共享能力。
"""

import json
import time
import uuid

from web_checks import analyze_cors, missing_security_headers

from .base import Detector, register

# 敏感字段检测模式(原 scanner.py 模块常量,info-leak 用)
SENSITIVE_PATTERNS = [
    ("password", "密码字段泄露"),
    ("secret", "密钥字段泄露"),
    ("token", "令牌字段泄露"),
    ("hash", "哈希字段可能泄露"),
    ("private_key", "私钥字段泄露"),
    ("api_key", "API 密钥字段泄露"),
    ("access_token", "访问令牌泄露"),
    ("refresh_token", "刷新令牌泄露"),
    ("totp_secret", "2FA 密钥泄露"),
    ("recovery_code", "恢复码泄露"),
]


@register
class AuthBypassDetector(Detector):
    name = "auth-bypass"
    owasp = "API2:2023"
    severity = "high"

    def run(self, ctx):
        endpoints = ctx.jwt
        print(f"\n🔍 AUTH-BYPASS: 打 {len(endpoints)} 个 JWT 端点 (无 token)")
        for ep in endpoints:
            p = ctx._resolve(ep["path"])
            body = {"note": "scan"} if ep["method"] in ("POST", "PUT") else None
            s, _, _ = ctx._req(ep["method"], p, body)
            ctx.stats["total"] += 1
            if s in (401, 403):
                ctx.stats["passed"] += 1
            elif s == 0:
                ctx._add("medium", self.name, p, ep["method"], "连接失败 (目标不可达?)")
                ctx.stats["errors"] += 1
            else:
                ctx._add("high", self.name, p, ep["method"],
                         f"无 token 返回 {s} (预期 401/403) — authMW 缺失?")


@register
class OpsEscalationDetector(Detector):
    name = "ops-escalate"
    owasp = "API5:2023"
    severity = "critical"

    def run(self, ctx):
        endpoints = ctx.admin
        print(f"\n🔍 OPS-ESCALATE: 打 {len(endpoints)} 个 admin 端点 (buyer token)")
        if not ctx.buyer_token:
            ctx.buyer_token, _, _ = ctx._register("buyer")
            print(f"   buyer token: {ctx.buyer_token[:24]}…")

        for ep in endpoints:
            p = ctx._resolve(ep["path"])
            body = None
            if ep["method"] in ("POST", "PUT"):
                body = {"note": "scan", "reason": "test", "approve": True}
            s, resp, _ = ctx._req(ep["method"], p, body, token=ctx.buyer_token)
            ctx.stats["total"] += 1
            if s in (401, 403):
                ctx.stats["passed"] += 1
            elif s == 0:
                ctx._add("medium", self.name, p, ep["method"], "连接失败")
                ctx.stats["errors"] += 1
            else:
                ctx._add("critical", self.name, p, ep["method"],
                         f"buyer token → {s} (预期 403). 缺少 authMW 或 opsGate!")


@register
class RateLimitDetector(Detector):
    name = "rate-bypass"
    owasp = "API4:2023"
    severity = "medium"
    slow = True

    def run(self, ctx):
        endpoints = ctx.rated
        print(f"\n🔍 RATE-BYPASS: 打 {len(endpoints)} 个限流端点")
        for ep in endpoints:
            rl = ep.get("rate_limit", {})
            limit = rl.get("limit", 10)
            reason = rl.get("reason", "?")
            p = ctx._resolve(ep["path"])
            token = getattr(ctx, "token", None)  # 有 token 则带上,测 auth 后面的限流
            body = {"note": "scan"} if ep["method"] in ("POST", "PUT") else None
            ctx.stats["total"] += 1
            hit = False
            last = 0
            for _ in range(limit + 1):
                s, _, _ = ctx._req(ep["method"], p, body, token=token)
                last = s
                if s == 429:
                    hit = True
                    break
                if s >= 500:
                    break
                time.sleep(0.06)
            if hit:
                ctx.stats["passed"] += 1
            elif last in (401, 403) and not token:
                # 端点被鉴权挡住(限流在 authMW 之后),无 token 测不到 → 不算缺失
                print(f"   ⏭  {p} 需鉴权(全程 {last}),限流在认证之后,带 --token/--login 才能测")
                ctx.stats["passed"] += 1
            else:
                ctx._add("medium", self.name, p, ep["method"],
                         f"连打 {limit+1} 次未触发 429 ({reason}) — 限流缺失或阈值过高")


@register
class IdorDetector(Detector):
    name = "idor"
    owasp = "API1:2023"
    severity = "high"
    slow = True

    def run(self, ctx):
        print("\n🔍 IDOR: 跨用户访问检测")
        ta, ua, _ = ctx._register("A")
        tb, ub, eb = ctx._register("B")
        print(f"   A={ua[:8]}…  B={ub[:8]}… ({eb})")

        tests = [
            ("/users/me/notifications/{id}/read", "POST", {}, "notification IDOR"),
            ("/questions/{id}/answer", "POST", {"body": "scan"}, "Q&A IDOR"),
        ]
        for opath, method, body, label in tests:
            p = opath.replace("{id}", "bogus-" + uuid.uuid4().hex[:8])
            s, _, _ = ctx._req(method, p, body, token=tb)
            ctx.stats["total"] += 1
            if s in (401, 403, 404):
                ctx.stats["passed"] += 1
            else:
                ctx._add("high", self.name, p, method,
                         f"{label}: B token → {s} (预期 4xx)")


@register
class InfoLeakDetector(Detector):
    name = "info-leak"
    owasp = "API3:2023"
    severity = "medium"

    def run(self, ctx):
        print("\n🔍 INFO-LEAK: 公共端点响应检测")
        probes = [("GET", "/datasets?limit=5"), ("GET", "/search?q=test"),
                  ("GET", "/verify/bogus-cert")]
        for method, path in probes:
            s, body, _ = ctx._req(method, path)
            ctx.stats["total"] += 1
            resp_str = json.dumps(body).lower()
            leaked = [(k, why) for k, why in SENSITIVE_PATTERNS if k in resp_str]
            if leaked:
                fields = ", ".join(k for k, _ in leaked)
                ctx._add("medium", self.name, path, method,
                         f"响应含敏感字段: {fields}",
                         evidence=json.dumps(body, ensure_ascii=False)[:200])
            else:
                ctx.stats["passed"] += 1


@register
class SecurityHeadersDetector(Detector):
    name = "sec-headers"
    owasp = "API8:2023"
    severity = "medium"

    def run(self, ctx, probe_path: str = "/"):
        print("\n🔍 SEC-HEADERS: 安全响应头检测")
        status, headers = ctx._get_headers(probe_path)
        ctx.stats["total"] += 1
        if status == 0:
            ctx._add("medium", self.name, probe_path, "GET", "连接失败 (目标不可达?)")
            ctx.stats["errors"] += 1
            return
        missing = missing_security_headers(headers)
        if not missing:
            ctx.stats["passed"] += 1
            return
        for name, desc, sev in missing:
            ctx._add(sev, self.name, probe_path, "GET", desc, evidence=name)


@register
class CorsDetector(Detector):
    name = "cors"
    owasp = "API8:2023"
    severity = "high"

    def run(self, ctx, probe_path: str = "/"):
        print("\n🔍 CORS: 跨域配置检测")
        evil = "https://evil.example"
        status, headers = ctx._get_headers(probe_path, extra={"Origin": evil})
        ctx.stats["total"] += 1
        if status == 0:
            ctx._add("medium", self.name, probe_path, "GET", "连接失败 (目标不可达?)")
            ctx.stats["errors"] += 1
            return
        issue = analyze_cors(evil, headers)
        if issue is None:
            ctx.stats["passed"] += 1
            return
        desc, sev = issue
        ctx._add(sev, self.name, probe_path, "GET", desc, evidence=f"Origin: {evil}")
