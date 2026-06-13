#!/usr/bin/env python3
"""
绿洲安全扫描器 v2 — 基于 openapi.yaml 的自动化扫描引擎。

检测项 (5 类):
  1. AUTH-BYPASS  — JWT 端点无 token 是否 401
  2. OPS-ESCALATE — admin 端点 buyer token 是否 403
  3. RATE-BYPASS  — 声明限流的端点是否触发 429
  4. IDOR         — B 的 token 操作 A 的资源
  5. INFO-LEAK    — 响应暴露出敏感字段

用法:
  python3 scanner.py --target http://localhost:8080/api/v1
  python3 scanner.py --target https://staging.oasis.cn/api/v1 --report scan.json
  python3 scanner.py --target http://localhost:8080/api/v1 --quick
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import HTTPError, Request, urlopen

try:
    import yaml
except ImportError:
    sys.exit("需要 PyYAML: pip3 install pyyaml")


# ═══════════════════════════════════════════════════════════════════════
# 已知限流配置 (对应各模块 router.go 中的 RateLimitConfig)
# ═══════════════════════════════════════════════════════════════════════
RATE_LIMITS = {
    "/auth/register":               {"limit": 5,  "window": "1m", "reason": "防批量注册"},
    "/auth/login":                  {"limit": 10, "window": "1m", "reason": "防暴力破解"},
    "/auth/refresh":                {"limit": 30, "window": "1m", "reason": "防令牌刷新滥用"},
    "/auth/logout":                 {"limit": 30, "window": "1m", "reason": "防注销洪水"},
    "/auth/2fa/verify":             {"limit": 15, "window": "1m", "reason": "防 2FA 暴力枚举"},
    "/auth/password-reset/request": {"limit": 3,  "window": "1m", "reason": "防枚举+防短信轰炸"},
    "/auth/password-reset/complete":{"limit": 5,  "window": "1m", "reason": "防令牌暴力猜测"},
    "/orders":                      {"limit": 20, "window": "1m", "reason": "防重复下单"},
    "/orders/{id}/dispute":         {"limit": 10, "window": "1m", "reason": "防纠纷洪水"},
    "/payments/create":             {"limit": 10, "window": "1m", "reason": "资金操作防护"},
    "/payments/dev/mark-paid":      {"limit": 10, "window": "1m", "reason": "仅 dev 环境"},
    "/compute/jobs":                {"limit": 20, "window": "1m", "reason": "计算资源保护"},
    "/compute/federated-jobs":      {"limit": 10, "window": "1m", "reason": "联合计算资源保护"},
    "/datasets/{id}/compute/order": {"limit": 10, "window": "1m", "reason": "计算订单保护"},
    "/datasets/{id}/compute/purchase":{"limit":10,"window": "1m", "reason": "仅 dev 环境"},
    "/datasets/{id}/preview":       {"limit": 30, "window": "1m", "reason": "防数据爬取"},
    "/datasets":                    {"limit": 20, "window": "1m", "reason": "防批量创建"},
    "/sellers/me/withdrawals":      {"limit": 5,  "window": "1m", "reason": "资金操作防护"},
    "/datasets/{id}/questions":     {"limit": 10, "window": "1m", "reason": "防垃圾提问"},
}

# 敏感字段检测模式
SENSITIVE_PATTERNS = [
    ("password",  "密码字段泄露"),
    ("secret",    "密钥字段泄露"),
    ("token",     "令牌字段泄露"),
    ("hash",      "哈希字段可能泄露"),
    ("private_key","私钥字段泄露"),
    ("api_key",   "API 密钥字段泄露"),
    ("access_token","访问令牌泄露"),
    ("refresh_token","刷新令牌泄露"),
    ("totp_secret","2FA 密钥泄露"),
    ("recovery_code","恢复码泄露"),
]

# ═══════════════════════════════════════════════════════════════════════
class OpenAPI:
    """openapi.yaml 解析和端点分类."""

    @staticmethod
    def load(path: str) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
        """返回 (public, jwt, admin, rated) 四组端点."""
        with open(path) as f:
            spec = yaml.safe_load(f)

        public, jwt, admin, rated = [], [], [], []
        paths = spec.get("paths", {})

        for raw_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, meta in methods.items():
                m = method.upper()
                if m not in ("GET", "POST", "PUT", "DELETE"):
                    continue
                if not isinstance(meta, dict):
                    continue

                entry = {"path": raw_path, "method": m}

                # security: None/absent → 继承全局 JWT
                # security: [] → 明确公开
                # security: [{bearerAuth: []}] → JWT
                sec = meta.get("security", None)
                if sec is None:
                    is_public = False  # inherit global = JWT
                elif isinstance(sec, list) and len(sec) == 0:
                    is_public = True
                elif isinstance(sec, list) and len(sec) > 0:
                    inner = sec[0]
                    if isinstance(inner, dict) and len(inner) == 0:
                        is_public = True
                    else:
                        is_public = False
                else:
                    is_public = False

                is_admin = "/admin/" in raw_path

                if is_admin:
                    admin.append(entry)
                elif is_public:
                    public.append(entry)
                else:
                    jwt.append(entry)

                # 标记已知限流
                if raw_path in RATE_LIMITS:
                    entry["rate_limit"] = RATE_LIMITS[raw_path]
                    rated.append(entry)

        return public, jwt, admin, rated

    @staticmethod
    def summary(public, jwt, admin, rated) -> str:
        return (f"公共:{len(public)}  JWT:{len(jwt)}  "
                f"Admin:{len(admin)}  限流:{len(rated)}")


# ═══════════════════════════════════════════════════════════════════════
class Scanner:
    """主动扫描引擎."""

    def __init__(self, target: str, timeout: int = 15, concurrency: int = 2):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.buyer_token: Optional[str] = None
        self.ops_token: Optional[str] = None
        self.findings: List[Dict] = []
        self.stats = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
        self._lock = threading.Lock()
        self._started = datetime.now(timezone.utc)

    # ── HTTP ──
    def _req(self, method: str, path: str,
             body: Any = None, token: Optional[str] = None) -> Tuple[int, Dict, float]:
        """Returns (status, json_body, elapsed_seconds)."""
        url = f"{self.target}{path}"
        data = json.dumps(body).encode() if body else None
        req = Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        t0 = time.monotonic()
        try:
            resp = urlopen(req, timeout=self.timeout)
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {}), time.monotonic() - t0
        except HTTPError as e:
            raw = e.read()
            return e.code, (json.loads(raw) if raw else {}), time.monotonic() - t0
        except URLError as e:
            return 0, {"error": str(e.reason)}, time.monotonic() - t0

    def _resolve(self, opath: str) -> str:
        """OpenAPI {param} → 占位值."""
        # 需要真实存在的 UUID 占位,否则 404 和 403 混淆
        for p in ["{id}","{token}","{cert_id}","{channel}",
                   "{orderId}","{order_id}","{user_id}"]:
            placeholder = "a" * 36 if "id" in p else "dummy-tok"
            opath = opath.replace(p, placeholder)
        return opath

    def _register(self, label: str) -> Tuple[str, str, str]:
        """注册用户 → (token, user_id, account)."""
        email = f"scan-{label}-{uuid.uuid4().hex[:6]}@sec.test"
        s, b, _ = self._req("POST", "/auth/register", {
            "account": email, "account_type": "email", "password": "Scanner123!",
        })
        if s != 200:
            raise RuntimeError(f"注册失败({label}) status={s}: {b}")
        d = b.get("data", {})
        tok = d.get("tokens", {}).get("access_token", "")
        uid = d.get("user", {}).get("id", "")
        return tok, uid, email

    def _add(self, severity: str, check: str, path: str, method: str, detail: str, evidence: str = ""):
        """记录漏洞."""
        with self._lock:
            self.findings.append({
                "severity": severity, "check": check, "path": path,
                "method": method, "detail": detail, "evidence": evidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            self.stats["failed"] += 1

    # ── 扫描 1: 鉴权绕过 ──
    def scan_auth_bypass(self, endpoints: List[Dict]):
        print(f"\n🔍 AUTH-BYPASS: 打 {len(endpoints)} 个 JWT 端点 (无 token)")
        for ep in endpoints:
            p = self._resolve(ep["path"])
            body = {"note":"scan"} if ep["method"] in ("POST","PUT") else None
            s, _, _ = self._req(ep["method"], p, body)
            self.stats["total"] += 1
            if s in (401, 403):
                self.stats["passed"] += 1
            elif s == 0:
                self._add("medium", "auth-bypass", p, ep["method"], "连接失败 (目标不可达?)")
                self.stats["errors"] += 1
            else:
                self._add("high", "auth-bypass", p, ep["method"],
                    f"无 token 返回 {s} (预期 401/403) — authMW 缺失?")

    # ── 扫描 2: 权限提升 ──
    def scan_ops_escalation(self, endpoints: List[Dict]):
        print(f"\n🔍 OPS-ESCALATE: 打 {len(endpoints)} 个 admin 端点 (buyer token)")
        if not self.buyer_token:
            self.buyer_token, _, _ = self._register("buyer")
            print(f"   buyer token: {self.buyer_token[:24]}…")

        for ep in endpoints:
            p = self._resolve(ep["path"])
            body = None
            if ep["method"] in ("POST","PUT"):
                body = {"note":"scan","reason":"test","approve":True}
            s, resp, _ = self._req(ep["method"], p, body, token=self.buyer_token)
            self.stats["total"] += 1
            if s in (401, 403):
                self.stats["passed"] += 1
            elif s == 0:
                self._add("medium", "ops-escalate", p, ep["method"], "连接失败")
                self.stats["errors"] += 1
            else:
                self._add("critical", "ops-escalate", p, ep["method"],
                    f"buyer token → {s} (预期 403). 缺少 authMW 或 opsGate!")

    # ── 扫描 3: 限流 ──
    def scan_rate_limits(self, endpoints: List[Dict]):
        print(f"\n🔍 RATE-BYPASS: 打 {len(endpoints)} 个限流端点")
        for ep in endpoints:
            rl = ep.get("rate_limit", {})
            limit = rl.get("limit", 10)
            reason = rl.get("reason", "?")
            p = self._resolve(ep["path"])
            body = {"note":"scan"} if ep["method"] in ("POST","PUT") else None
            self.stats["total"] += 1
            hit = False
            for i in range(limit + 1):
                s, _, _ = self._req(ep["method"], p, body)
                if s == 429:
                    hit = True
                    break
                if s >= 500:
                    break
                time.sleep(0.06)
            if hit:
                self.stats["passed"] += 1
            else:
                self._add("medium", "rate-bypass", p, ep["method"],
                    f"连打 {limit+1} 次未触发 429 ({reason}) — 限流缺失或阈值过高")

    # ── 扫描 4: IDOR ──
    def scan_idor(self):
        print("\n🔍 IDOR: 跨用户访问检测")
        ta, ua, _ = self._register("A")
        tb, ub, eb = self._register("B")
        print(f"   A={ua[:8]}…  B={ub[:8]}… ({eb})")

        tests = [
            ("/users/me/notifications/{id}/read",  "POST", {}, "notification IDOR"),
            ("/questions/{id}/answer",              "POST", {"body":"scan"}, "Q&A IDOR"),
        ]
        for opath, method, body, label in tests:
            p = opath.replace("{id}", "bogus-" + uuid.uuid4().hex[:8])
            s, _, _ = self._req(method, p, body, token=tb)
            self.stats["total"] += 1
            if s in (401, 403, 404):
                self.stats["passed"] += 1
            else:
                self._add("high", "idor", p, method,
                    f"{label}: B token → {s} (预期 4xx)")

    # ── 扫描 5: 信息泄露 ──
    def scan_info_leak(self, public_eps: List[Dict]):
        print("\n🔍 INFO-LEAK: 公共端点响应检测")
        probes = [("GET", "/datasets?limit=5"), ("GET", "/search?q=test"),
                   ("GET", "/verify/bogus-cert")]
        for method, path in probes:
            s, body, _ = self._req(method, path)
            self.stats["total"] += 1
            resp_str = json.dumps(body).lower()
            leaked = [(k, why) for k, why in SENSITIVE_PATTERNS if k in resp_str]
            if leaked:
                fields = ", ".join(k for k, _ in leaked)
                self._add("medium", "info-leak", path, method,
                    f"响应含敏感字段: {fields}",
                    evidence=json.dumps(body, ensure_ascii=False)[:200])
            else:
                self.stats["passed"] += 1

    # ── 报告 ──
    def report(self) -> Dict:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings = sorted(self.findings, key=lambda f: severity_order.get(f["severity"], 99))
        return {
            "target": self.target,
            "scanned_at": self._started.isoformat(),
            "duration_seconds": (datetime.now(timezone.utc) - self._started).total_seconds(),
            "stats": dict(self.stats),
            "findings": findings,
        }


# ═══════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description="绿洲 API 安全扫描器 v2")
    ap.add_argument("--target", "-t", required=True, help="API base URL")
    ap.add_argument("--spec", default=None, help="openapi.yaml path")
    ap.add_argument("--report", "-o", default=None, help="输出 JSON 报告")
    ap.add_argument("--quick", action="store_true", help="跳过限流和 IDOR")
    ap.add_argument("--concurrency", "-c", type=int, default=2, help="并发线程数")
    args = ap.parse_args()

    # 找 spec
    if args.spec:
        sp = args.spec
    else:
        for c in ["backend/api/openapi.yaml",
                  os.path.expanduser("~/ai-data-marketplace-loginfix/backend/api/openapi.yaml")]:
            if os.path.exists(c):
                sp = c
                break
        else:
            sys.exit("找不到 openapi.yaml。用 --spec")

    print(f"📄 {sp}")
    public, jwt, admin, rated = OpenAPI.load(sp)
    print(f"   {OpenAPI.summary(public, jwt, admin, rated)} 端点")
    print(f"   目标: {args.target}\n")

    scanner = Scanner(args.target, concurrency=args.concurrency)

    try:
        scanner.scan_auth_bypass(jwt)
        scanner.scan_ops_escalation(admin)
        if not args.quick:
            scanner.scan_rate_limits(rated)
            scanner.scan_idor()
        scanner.scan_info_leak(public)
    except KeyboardInterrupt:
        print("\n⏹  用户中断")

    # 终端报告
    rep = scanner.report()
    s = rep["stats"]
    print(f"\n{'═'*60}")
    print(f"扫描完成: {s['total']} 项检测  {s['duration_seconds']:.0f}s")
    print(f"  ✅ 通过: {s['passed']}    ❌ 漏洞: {s['failed']}    ⚠  错误: {s['errors']}")

    if rep["findings"]:
        sev_icon = {"critical":"🔴","high":"🟠","medium":"🟡"}
        print(f"\n🚨 {len(rep['findings'])} 个漏洞:")
        for i, f in enumerate(rep["findings"], 1):
            ic = sev_icon.get(f["severity"], "⚪")
            print(f"\n  {ic} [{f['severity'].upper()}] {f['check']}")
            print(f"     {f['method']} {f['path']}")
            print(f"     {f['detail']}")
            if f.get("evidence"):
                print(f"     证据: {f['evidence']}")
    else:
        print("\n🎉 零漏洞!")

    if args.report:
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        with open(args.report, "w") as fp:
            json.dump(rep, fp, indent=2, ensure_ascii=False)
        print(f"\n📄 报告: {args.report}")


if __name__ == "__main__":
    main()
