"""P1: JWT 鉴权检测器(OWASP API2)。

策略:需要一个有效 JWT 作基准(来自 ctx.token,即 CLI 的 --token)。
对每个 JWT(authenticated)端点发去伪造变体,若被接受(2xx)即判为漏洞。
无 --token 时跳过(无法构造伪造基准)。
"""

from .base import Detector, register
from .jwt_forge import forge_alg_none, forge_tampered, forge_unsigned


class _JwtForgeryDetector(Detector):
    """共享逻辑:对所有 JWT 端点发一种伪造 token,看是否被接受。"""
    owasp = "API2:2023"
    forge = None      # 子类提供: token -> 伪造 token
    detail = ""       # 命中时的说明

    def run(self, ctx):
        token = getattr(ctx, "token", None)
        print(f"\n🔍 {self.name.upper()}: JWT 伪造检测")
        if not token:
            print("   跳过: 未提供 --token(JWT 检测需要一个有效 token 作基准)")
            return
        if not ctx.jwt:
            print("   跳过: spec 里没有 JWT(authenticated)端点")
            return
        try:
            forged = type(self).forge(token)
        except Exception as e:
            print(f"   跳过: 无法解析 token ({e})")
            return

        for ep in ctx.jwt:
            p = ctx._resolve(ep["path"])
            s, _, _ = ctx._req(ep["method"], p, token=forged)
            ctx.stats["total"] += 1
            if s == 0:
                ctx._add("medium", self.name, p, ep["method"], "连接失败 (目标不可达?)")
                ctx.stats["errors"] += 1
            elif 200 <= s < 300:
                ctx._add(self.severity, self.name, p, ep["method"], self.detail,
                         evidence=forged[:60] + "…")
            else:
                ctx.stats["passed"] += 1


@register
class JwtAlgNoneDetector(_JwtForgeryDetector):
    name = "jwt-alg-none"
    severity = "critical"
    forge = staticmethod(forge_alg_none)
    detail = "alg=none 伪造 token 被接受 — 服务端信任 header 声明的算法"


@register
class JwtUnsignedDetector(_JwtForgeryDetector):
    name = "jwt-unsigned"
    severity = "critical"
    forge = staticmethod(forge_unsigned)
    detail = "空签名 token 被接受 — 服务端未要求有效签名"


@register
class JwtSigNotVerifiedDetector(_JwtForgeryDetector):
    name = "jwt-sig-not-verified"
    severity = "critical"
    forge = staticmethod(forge_tampered)
    detail = "篡改 payload(提权)+ 原签名被接受 — 服务端未校验签名"
