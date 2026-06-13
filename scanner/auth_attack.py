#!/usr/bin/env python3
"""
Ember 授权攻击扫描器 — 自动获取会话,以认证身份执行完整攻击链。

用法:
  python3 scanner/auth_attack.py -t http://localhost:3000 --dvwa
  python3 scanner/auth_attack.py -t http://localhost:8080/api/v1 --oasis
"""

import json, sys, time, os, re
from typing import Optional, List, Dict, Tuple
from urllib.request import Request, urlopen, HTTPError
from urllib.error import URLError
from urllib.parse import urljoin
from pathlib import Path

# 靶场预设
PRESETS = {
    "dvwa": {
        "login_path": "/login.php",
        "login_body": "username=admin&password=password&Login=Login",
        "login_method": "POST",
        "token_extractor": lambda body: re.search(r'PHPSESSID=([a-f0-9]+)', body, re.I).group(1) if re.search(r'PHPSESSID=([a-f0-9]+)', body, re.I) else None,
        "token_type": "cookie",
        "security_path": "/security.php",
        "set_security": "security=low&seclev_submit=Submit",
        "vuln_endpoints": [
            "/vulnerabilities/sqli/?id=",
            "/vulnerabilities/sqli_blind/?id=",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
            "/vulnerabilities/cmdi/",
            "/vulnerabilities/upload/",
        ],
    },
    "juice": {
        "login_path": "/rest/user/login",
        "login_body": '{"email":"admin@juice-sh.op","password":"admin123"}',
        "login_method": "POST",
        "token_extractor": lambda body: (json.loads(body).get("authentication", {}).get("token") if body else None),
        "token_type": "bearer",
        "vuln_endpoints": [
            "/rest/products/search?q=",
            "/rest/user/whoami",
            "/api/Users",
            "/rest/basket/1",
            "/rest/review",
            "/rest/track-order/",
            "/rest/user/change-password",
            "/rest/user/erasure-request",
        ],
    },
    "oasis": {
        "login_path": "/auth/register",
        "login_body": '{"account":"ember-scan@sec.test","account_type":"email","password":"Scanner123!"}',
        "login_method": "POST",
        "token_extractor": lambda body: (json.loads(body).get("data", {}).get("tokens", {}).get("access_token") if body else None),
        "token_type": "bearer",
        "vuln_endpoints": [
            "/orders?role=seller",
            "/sellers/me/withdrawals",
            "/sellers/me/earnings",
            "/users/me",
            "/users/me/notifications",
            "/users/me/data-export",
            "/users/me/account/deletion",
            "/datasets/{id}",
        ],
    },
}


class AuthAttacker:
    """获取认证令牌,以合法用户身份执行攻击链."""

    def __init__(self, target: str, preset: str = "dvwa", timeout: int = 15):
        self.target = target.rstrip("/")
        self.preset = PRESETS.get(preset, {})
        self.timeout = timeout
        self.token: Optional[str] = None
        self.cookies: Dict[str, str] = {}
        self.findings: List[Dict] = []
        self._prep_session()

    def _req(self, method: str, path: str, data: Optional[str] = None,
             ct: str = "application/x-www-form-urlencoded") -> Tuple[int, str]:
        url = self.target + path
        req = Request(url, data=data.encode() if data else None, method=method)
        req.add_header("Content-Type", ct)
        if self.token:
            token_type = self.preset.get("token_type", "bearer")
            if token_type == "bearer":
                req.add_header("Authorization", f"Bearer {self.token}")
            elif token_type == "cookie":
                req.add_header("Cookie", f"PHPSESSID={self.token}; security=low")
        try:
            resp = urlopen(req, timeout=self.timeout)
            return resp.status, resp.read().decode(errors="replace")
        except HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except URLError as e:
            return 0, str(e.reason)

    def _prep_session(self):
        """获取认证令牌."""
        if not self.preset:
            print("⚠️ 无靶场预设,跳过认证")
            return

        print(f"🔑 登录 {self.preset['login_path']} …")
        status, body = self._req(
            self.preset["login_method"],
            self.preset["login_path"],
            self.preset["login_body"],
            "application/json" if "{" in self.preset["login_body"] else "application/x-www-form-urlencoded",
        )

        extractor = self.preset.get("token_extractor")
        if extractor:
            self.token = extractor(body)
        
        if self.token:
            print(f"   ✅ 已认证: {self.token[:24]}…")
        else:
            print(f"   ❌ 认证失败 (status={status})")
            if len(body) < 500:
                print(f"   body: {body}")

    # ── 攻击链 ──

    def scan_auth_bypass_idor(self):
        """用合法用户的 token 尝试访问其他用户的资源 (IDOR)."""
        print(f"\n🔍 IDOR 扫描 …")
        idor_tests = [
            # DVWA
            ("GET", "/vulnerabilities/sqli/?id=2&Submit=Submit"),
            # Oasis — 用买家 token 打 seller 端点
            ("GET", "/sellers/me/withdrawals"),
            ("GET", "/sellers/me/earnings"),
            ("POST", "/sellers/me/withdrawals", '{"amount_cents":1,"channel":"bank","account_label":"scan"}'),
            # 用用户 A 的 token 访问用户 B 的资源
            ("POST", "/users/me/data-export"),
            ("POST", "/users/me/account/deletion", '{"reason":"scan"}'),
        ]
        for t in idor_tests:
            method, path = t[0], t[1]
            body = t[2] if len(t) > 2 else None
            s, resp = self._req(method, path, body,
                              "application/json" if body and "{" in body else "application/x-www-form-urlencoded")
            if s < 400 and len(resp) > 50:
                self.findings.append({
                    "check": "idor",
                    "severity": "high",
                    "method": method,
                    "path": path,
                    "status": s,
                    "detail": f"IDOR 风险: {path} 返回 {s}, 响应 {len(resp)} 字节",
                })

    def scan_rate_limits(self):
        """连打端点检测限流失效."""
        print(f"\n🔍 限流检测 …")
        rate_tests = [
            ("/orders", "POST", '{"dataset_id":"x","license_type":"commercial"}'),
            ("/sellers/me/withdrawals", "POST", '{"amount_cents":1,"channel":"bank","account_label":"scan"}'),
            ("/users/me/data-export", "POST", ""),
            ("/users/me/account/deletion", "POST", '{"reason":"scan"}'),
        ]
        for path, method, body in rate_tests:
            hit_429 = False
            for i in range(12):
                s, _ = self._req(method, path, body,
                               "application/json" if "{" in body else "application/x-www-form-urlencoded")
                if s == 429:
                    hit_429 = True
                    break
                if s == 404:  # endpoint doesn't exist
                    break
                time.sleep(0.06)
            if not hit_429 and s != 404:
                self.findings.append({
                    "check": "rate-limit",
                    "severity": "medium",
                    "method": method,
                    "path": path,
                    "detail": f"12 次请求未触发 429 — 限流可能缺失",
                })

    def scan_info_leak(self):
        """检查公共端点是否泄露敏感信息."""
        print(f"\n🔍 信息泄露 …")
        public_probes = [
            "/datasets",
            "/datasets?limit=5",
            "/search?q=test",
            "/verify/bogus-cert",
        ]
        sensitive = ["password", "secret", "token", "hash", "private_key", "totp"]
        for path in public_probes:
            s, body = self._req("GET", path, ct="application/json")
            leaked = [k for k in sensitive if k in body.lower()]
            if leaked:
                self.findings.append({
                    "check": "info-leak",
                    "severity": "medium",
                    "method": "GET",
                    "path": path,
                    "detail": f"响应含敏感字段: {', '.join(leaked)}",
                })

    def full_scan(self) -> Dict:
        """完整的授权攻击扫描."""
        self.scan_auth_bypass_idor()
        self.scan_rate_limits()
        self.scan_info_leak()
        return {
            "target": self.target,
            "preset": list(PRESETS.keys())[0] if self.preset else "custom",
            "authenticated": bool(self.token),
            "findings": self.findings,
        }


# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ember 授权攻击扫描器")
    ap.add_argument("-t", "--target", default="http://localhost:4280")
    ap.add_argument("--dvwa", action="store_true", help="DVWA 靶场模式")
    ap.add_argument("--juice", action="store_true", help="Juice Shop 靶场模式")
    ap.add_argument("--oasis", action="store_true", help="Oasis 模式")
    ap.add_argument("--full", action="store_true", help="完整扫描")
    ap.add_argument("--rate-only", action="store_true", help="仅限流检测")
    args = ap.parse_args()

    preset = "dvwa" if args.dvwa else ("juice" if args.juice else ("oasis" if args.oasis else "dvwa"))
    attacker = AuthAttacker(args.target, preset)

    if not attacker.token:
        print("\n❌ 认证失败 — 无法执行授权攻击")
        sys.exit(1)

    if args.full or args.oasis:
        result = attacker.full_scan()
    elif args.rate_only:
        attacker.scan_rate_limits()
        result = {"target": args.target, "findings": attacker.findings}
    else:
        attacker.scan_auth_bypass_idor()
        attacker.scan_rate_limits()
        result = {"target": args.target, "findings": attacker.findings}

    print(f"\n{'═'*60}")
    findings = attacker.findings
    print(f"授权扫描完成: {len(findings)} 个发现")
    for f in findings:
        icon = {"high": "🔴", "medium": "🟡", "low": "⚪"}.get(f["severity"], "?")
        print(f"  {icon} [{f['severity']}] {f['check']}: {f['path']}")
        print(f"     {f['detail']}")
