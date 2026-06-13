"""P2: 对象属性级授权(OWASP API6)—— mass assignment。

注:对象级授权(BOLA/API1)已由 legacy 的 `idor` 检测器覆盖;
这里补的是未覆盖的 mass assignment —— 客户端注入特权字段被服务端盲接受。

策略:对写端点(POST/PUT)发一个带特权字段的请求体,若响应回显了被注入的
特权字段=被注入的值,即认为服务端做了 mass assignment(把用户可控字段直接落库)。
"""

import json

from .base import Detector, register

# 常见的"不该由客户端设置"的特权字段 → 注入值
PRIVILEGED_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "is_staff": True,
    "is_active": True,
    "is_verified": True,
    "verified": True,
    "balance": 999999,
    "credit": 999999,
}


def reflected_privileged_fields(response_body) -> list:
    """响应里被原样回显的特权字段(名=注入值)。纯函数,便于单测。"""
    if not isinstance(response_body, dict):
        return []
    # 兼容 {data: {...}} 包裹
    candidates = [response_body]
    if isinstance(response_body.get("data"), dict):
        candidates.append(response_body["data"])
    hit = []
    for field, injected in PRIVILEGED_FIELDS.items():
        for obj in candidates:
            if field in obj and obj[field] == injected:
                hit.append(field)
                break
    return hit


@register
class MassAssignmentDetector(Detector):
    name = "mass-assignment"
    owasp = "API6:2023"
    severity = "high"

    def run(self, ctx):
        # 写端点: jwt + public 里的 POST/PUT
        writes = [ep for ep in (ctx.jwt + ctx.public) if ep["method"] in ("POST", "PUT")]
        print(f"\n🔍 MASS-ASSIGNMENT: 打 {len(writes)} 个写端点(注入特权字段)")
        body = {"name": "scan", **PRIVILEGED_FIELDS}
        for ep in writes:
            p = ctx._resolve(ep["path"])
            token = getattr(ctx, "token", None) or ctx.buyer_token
            s, resp, _ = ctx._req(ep["method"], p, body, token=token)
            ctx.stats["total"] += 1
            if s == 0:
                ctx._add("medium", self.name, p, ep["method"], "连接失败 (目标不可达?)")
                ctx.stats["errors"] += 1
                continue
            reflected = reflected_privileged_fields(resp)
            if reflected:
                ctx._add("high", self.name, p, ep["method"],
                         f"注入的特权字段被服务端接受并回显: {', '.join(reflected)}",
                         evidence=json.dumps(resp, ensure_ascii=False)[:200])
            else:
                ctx.stats["passed"] += 1
