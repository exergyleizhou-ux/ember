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
import logging
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import HTTPError, HTTPRedirectHandler, Request, build_opener, urlopen


class _NoRedirect(HTTPRedirectHandler):
    """不追随 3xx —— 用于检测 open redirect / Host 头注入时要看原始 Location。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

try:
    import yaml
except ImportError:
    sys.exit("需要 PyYAML: pip3 install pyyaml")

log = logging.getLogger("ember.scanner")


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

    def __init__(self, target: str, timeout: int = 15, concurrency: int = 2,
                 rate: float = 0.0, retries: int = 2):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.retries = retries
        self.buyer_token: Optional[str] = None
        self.ops_token: Optional[str] = None
        self.token: Optional[str] = None   # 有效 JWT 基准(--token),供 JWT 检测器
        self.findings: List[Dict] = []
        self.stats = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
        # 端点分组(由 main 在装载 spec 后填充;检测器从 ctx 读取)
        self.public: List[Dict] = []
        self.jwt: List[Dict] = []
        self.admin: List[Dict] = []
        self.rated: List[Dict] = []
        self._lock = threading.Lock()
        self._started = datetime.now(timezone.utc)
        # 限速: rate=每秒最大请求数;0 = 不限。防止打挂目标。
        self._min_interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._last_req = 0.0
        self._rate_lock = threading.Lock()

    def _throttle(self):
        """按 rate 在请求间插入最小间隔(线程安全)。"""
        if self._min_interval <= 0:
            return
        with self._rate_lock:
            wait = self._min_interval - (time.monotonic() - self._last_req)
            if wait > 0:
                time.sleep(wait)
            self._last_req = time.monotonic()

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

        attempt = 0
        while True:
            self._throttle()
            t0 = time.monotonic()
            try:
                resp = urlopen(req, timeout=self.timeout)
                raw = resp.read()
                log.debug("%s %s → %s", method, path, resp.status)
                return resp.status, (json.loads(raw) if raw else {}), time.monotonic() - t0
            except HTTPError as e:
                # HTTP 错误是真实响应,不重试
                raw = e.read()
                log.debug("%s %s → %s (http)", method, path, e.code)
                return e.code, (json.loads(raw) if raw else {}), time.monotonic() - t0
            except URLError as e:
                # 连接级错误: 退避重试,扛网络抖动
                if attempt < self.retries:
                    attempt += 1
                    backoff = 0.2 * attempt
                    log.debug("%s %s 连接失败 (%s),第 %d 次重试,退避 %.1fs",
                              method, path, e.reason, attempt, backoff)
                    time.sleep(backoff)
                    continue
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

    def acquire_token(self, login_url: str, body: Any, method: str = "POST",
                      token_path: Optional[str] = None) -> Optional[str]:
        """走登录流取 token,写入 self.token 并返回。失败返回 None。"""
        from auth import extract_token
        s, resp, _ = self._req(method, login_url, body)
        if not (200 <= s < 300):
            log.warning("登录失败 status=%s url=%s", s, login_url)
            return None
        tok = extract_token(resp, token_path)
        if tok:
            self.token = tok
        else:
            log.warning("登录成功但未能从响应提取 token(试试 --token-path)")
        return tok

    def _add(self, severity: str, check: str, path: str, method: str, detail: str, evidence: str = ""):
        """记录漏洞."""
        with self._lock:
            self.findings.append({
                "severity": severity, "check": check, "path": path,
                "method": method, "detail": detail, "evidence": evidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            self.stats["failed"] += 1

    # ── HTTP 头(被动检查用)──
    def _get_headers(self, path: str, extra: Optional[Dict] = None) -> Tuple[int, Dict]:
        """GET 一个端点,返回 (status, response_headers)。失败返回 (0, {})。"""
        url = f"{self.target}{path}"
        req = Request(url, method="GET")
        for k, v in (extra or {}).items():
            req.add_header(k, v)
        self._throttle()
        try:
            resp = urlopen(req, timeout=self.timeout)
            return resp.status, dict(resp.headers.items())
        except HTTPError as e:
            return e.code, dict(e.headers.items()) if e.headers else {}
        except URLError:
            return 0, {}

    def _raw_get(self, path: str, headers: Optional[Dict] = None,
                 follow_redirects: bool = False, method: str = "GET",
                 body: Any = None) -> Tuple[int, str, Dict]:
        """请求并返回 (status, body_text, headers);默认不追随 3xx 以便检查 Location。
        返回原始文本(不做 JSON 解析),适合探测可能返回非 JSON 的任意路径。"""
        url = f"{self.target}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        opener = urlopen if follow_redirects else build_opener(_NoRedirect()).open
        self._throttle()
        try:
            resp = opener(req, timeout=self.timeout)
            return resp.status, resp.read().decode(errors="replace"), dict(resp.headers.items())
        except HTTPError as e:
            body = e.read().decode(errors="replace") if e.fp else ""
            return e.code, body, dict(e.headers.items()) if e.headers else {}
        except URLError:
            return 0, "", {}

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
    ap.add_argument("--target", "-t", default=None, help="API base URL")
    ap.add_argument("--spec", default=None, help="openapi.yaml path")
    ap.add_argument("--report", "-o", default=None, help="输出 JSON 报告")
    ap.add_argument("--sarif", default=None, help="输出 SARIF 2.1.0 报告(供 CI / GitHub Code Scanning)")
    ap.add_argument("--quick", action="store_true", help="跳过慢检测器(限流/IDOR)")
    ap.add_argument("--concurrency", "-c", type=int, default=2, help="并发线程数")
    ap.add_argument("--rate", type=float, default=0.0, help="每秒最大请求数(限速,0=不限),防止打挂目标")
    ap.add_argument("--retries", type=int, default=2, help="连接失败的重试次数")
    ap.add_argument("--scope", default="", help="授权目标 allowlist(逗号分隔的主机/域名);本机始终允许")
    ap.add_argument("--token", default=None, help="有效 JWT(供 JWT 伪造检测器作基准)")
    ap.add_argument("--login-url", default=None, help="登录端点(自动取 token,免去手填 --token)")
    ap.add_argument("--login-body", default=None, help="登录请求体(JSON 字符串)")
    ap.add_argument("--login-method", default="POST", help="登录方法(默认 POST)")
    ap.add_argument("--token-path", default=None, help="响应里 token 的点路径(如 data.tokens.access_token);留空则自动发现")
    ap.add_argument("--verbose", "-v", action="store_true", help="输出每个请求的 debug 日志")
    ap.add_argument("--list-detectors", action="store_true", help="列出所有检测器并退出")
    ap.add_argument("--enable", default="", help="只跑这些检测器(逗号分隔的 name)")
    ap.add_argument("--disable", default="", help="跳过这些检测器(逗号分隔的 name)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # 检测器注册表(同级包,按 CLI 方式放上 path)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import detectors

    if args.list_detectors:
        print(f"{'NAME':<16}{'OWASP':<12}{'SEVERITY':<10}SLOW")
        for d in detectors.iter_detectors():
            print(f"{d.name:<16}{d.owasp:<12}{d.severity:<10}{'yes' if d.slow else ''}")
        return

    if not args.target:
        ap.error("--target/-t 必填(除非 --list-detectors)")

    # 授权护栏: 非本机目标必须显式授权
    from scope import UnauthorizedTargetError, parse_scope, require_authorized
    try:
        require_authorized(args.target, parse_scope(args.scope))
    except UnauthorizedTargetError as e:
        sys.exit(f"⛔ 授权检查失败:\n{e}")

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

    scanner = Scanner(args.target, concurrency=args.concurrency,
                      rate=args.rate, retries=args.retries)
    scanner.public, scanner.jwt, scanner.admin, scanner.rated = public, jwt, admin, rated
    scanner.token = args.token

    # 认证流自动取 token(优先于手填 --token)
    if args.login_url:
        login_body = json.loads(args.login_body) if args.login_body else {}
        tok = scanner.acquire_token(args.login_url, login_body, args.login_method, args.token_path)
        if tok:
            print(f"🔑 已自动获取 token: {tok[:24]}…")
        else:
            print("⚠️  认证流取 token 失败(JWT 检测器将跳过)")

    # 选择启用的检测器: --enable 白名单优先,其次 --disable 黑名单,--quick 跳过慢的
    enable = {x.strip() for x in args.enable.split(",") if x.strip()}
    disable = {x.strip() for x in args.disable.split(",") if x.strip()}
    selected = []
    for d in detectors.iter_detectors():
        if enable and d.name not in enable:
            continue
        if d.name in disable:
            continue
        if args.quick and d.slow:
            continue
        selected.append(d)

    try:
        for d in selected:
            d.run(scanner)
    except KeyboardInterrupt:
        print("\n⏹  用户中断")

    # 终端报告
    rep = scanner.report()
    s = rep["stats"]
    print(f"\n{'═'*60}")
    print(f"扫描完成: {s['total']} 项检测  {rep['duration_seconds']:.0f}s")
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

    if args.sarif:
        from sarif import to_sarif
        os.makedirs(os.path.dirname(args.sarif) or ".", exist_ok=True)
        with open(args.sarif, "w") as fp:
            json.dump(to_sarif(rep), fp, indent=2, ensure_ascii=False)
        print(f"📄 SARIF: {args.sarif}")


if __name__ == "__main__":
    main()
