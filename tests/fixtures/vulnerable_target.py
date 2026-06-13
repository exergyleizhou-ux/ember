#!/usr/bin/env python3
"""
故意做脆弱的靶机 — 仅用于在测试中验证 Ember 检测器的真伪。

设计原则:
  - 只用标准库 http.server,无外部依赖,任何机器都能跑。
  - 每个脆弱端点对应 Ember 的一类检测;同时提供"健康"对照端点,
    用来证明检测器在安全端点上不误报。
  - 漏洞是"可开关"的:VulnerableServer(vulns={...}) 选择启用哪几类漏洞,
    默认全关(完全安全),这样同一套端点既能测"检出"也能测"不误报"。
  - 绝不绑定真实数据;所有"漏洞"都是受控的字符串反射。

可开关的漏洞类别(对应 scanner/scanner.py 的检测项):
  "auth_bypass"     — JWT 端点无 token 也放行
  "ops_escalation"  — admin 端点不校验角色,buyer 也放行
  "idor"            — 跨用户资源访问不拦截

启动(供测试用):
    server = VulnerableServer(vulns={"idor"}).start()
    base = server.base_url           # http://127.0.0.1:<port>
    ...
    server.stop()
"""

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ── 最小 HS256 JWT(仅靶机用,验证 scanner 的 JWT 检测器)──
_JWT_SECRET = b"test-target-secret"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hs256(msg: str) -> str:
    return _b64u(hmac.new(_JWT_SECRET, msg.encode(), hashlib.sha256).digest())


def _issue_jwt() -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps({"sub": "u1", "role": "user", "exp": 9999999999}).encode())
    return f"{h}.{p}.{_hs256(f'{h}.{p}')}"


def _jwt_accepted(token: str, vulns) -> bool:
    """靶机的 JWT 校验:安全时只接受签名正确的 HS256;漏洞开关放宽对应路径。"""
    try:
        h_seg, p_seg, sig = token.split(".")
        alg = json.loads(_b64u_decode(h_seg)).get("alg")
    except Exception:
        return False
    if alg == "none":
        return "jwt_alg_none" in vulns
    if sig == "":
        return "jwt_unsigned" in vulns
    if hmac.compare_digest(sig, _hs256(f"{h_seg}.{p_seg}")):
        return True
    return "jwt_no_verify" in vulns

# 触发 Ember._analyze 报错检出的 MySQL 风格报错(含 "SQL syntax")
_SQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that "
    "corresponds to your MySQL server version for the right syntax"
)

# 任何包含这些片段的输入都视为 SQLi 探测,受控反射报错
_SQLI_MARKERS = ("'", '"', "--", "union", "sleep", "or 1=1", "drop")


def _looks_like_sqli(value: str) -> bool:
    low = value.lower()
    return any(m in low for m in _SQLI_MARKERS)


def _role_from_token(token: str) -> str:
    """token 形如 tok-<uid>-<role>;取不到则视为匿名。"""
    if not token:
        return "anonymous"
    parts = token.split("-")
    return parts[-1] if len(parts) >= 3 else "anonymous"


class _Handler(BaseHTTPRequestHandler):
    # 关掉默认 stderr 日志,保持测试输出干净
    def log_message(self, *args):
        pass

    @property
    def vulns(self) -> frozenset:
        return self.server.vulns

    # ── 工具 ──
    def _send(self, status: int, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return ""
        return self.rfile.read(length).decode(errors="replace")

    def _token(self) -> str:
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else ""

    def do_TRACE(self):
        # HTTP-METHOD 探测点: 脆弱时回显请求(XST),安全时 405
        if "trace_method" in self.server.vulns:
            body = f"TRACE {self.path} HTTP/1.1\r\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "message/http")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send(405, {"error": "method not allowed"})

    # ── 路由 ──
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        q = params.get("q", [""])[0]

        if path == "/search":
            # 脆弱: 把用户输入拼进"SQL",报错原样回吐 → 经典报错型 SQLi
            if _looks_like_sqli(q):
                if "sleep" in q.lower():
                    # 受控的时间盲注:延迟 2s,触发 time_based 检出
                    time.sleep(2.0)
                self._send(500, {"error": _SQL_ERROR, "query": q})
                return
            self._send(200, {"results": [], "query": q})
            return

        if path == "/safe":
            # 健康对照: 完全忽略输入,恒定响应 → 不应被任何检测器命中
            self._send(200, {"results": [], "ok": True})
            return

        if path == "/jwt/thing":
            # AUTH-BYPASS 探测点: 默认要求 token,开关打开则无 token 也放行
            if "auth_bypass" in self.vulns or self._token():
                self._send(200, {"ok": True})
            else:
                self._send(401, {"error": "missing token"})
            return

        if path == "/jwt-login":
            # 颁发一个真实 HS256 JWT,供 scanner 的 JWT 检测器作伪造基准
            self._send(200, {"token": _issue_jwt()})
            return

        if path == "/redirect":
            # OPEN-REDIRECT 探测点
            nxt = params.get("next", [""])[0]
            if "open_redirect" in self.vulns and nxt:
                self.send_response(302)
                self.send_header("Location", nxt)   # 脆弱: 直接信任用户输入
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(200, {"ok": True})        # 安全: 不外跳
            return

        if path == "/profile":
            # HOST-HEADER 探测点: 脆弱时把 Host 反射进正文(如重置链接)
            if "host_header" in self.vulns:
                host = self.headers.get("Host", "")
                self._send(200, {"reset_link": f"https://{host}/reset"})
            else:
                self._send(200, {"reset_link": "https://app.trusted.com/reset"})
            return

        if path == "/fetch":
            # SSRF 探测点: 脆弱时服务端去抓取 url 参数(回连扫描器的 OOB)
            url = params.get("url", [""])[0]
            if "ssrf" in self.vulns and url:
                try:
                    urllib.request.urlopen(url, timeout=2).read()
                except Exception:
                    pass
            self._send(200, {"ok": True})
            return

        if path == "/openapi.json":
            # DEBUG-EXPOSURE 探测点
            if "debug_exposure" in self.vulns:
                self._send(200, {"openapi": "3.0.0", "paths": {}})
            else:
                self._send(404, {"error": "not found"})
            return

        if path == "/error":
            # VERBOSE-ERRORS 探测点: 脆弱时回吐 python 栈
            if "verbose_errors" in self.vulns:
                self._send(500, {"error": 'Traceback (most recent call last):\n  '
                                          'File "/app/views.py", line 42, in handler'})
            else:
                self._send(400, {"error": "bad request"})
            return

        if path == "/jwt/protected":
            # JWT 校验点: 安全时拒绝一切伪造,漏洞开关放行对应伪造
            if _jwt_accepted(self._token(), self.vulns):
                self._send(200, {"ok": True})
            else:
                self._send(401, {"error": "invalid token"})
            return

        # 安全响应头检测对照点
        if path == "/headers/secure":
            self._send(200, {"ok": True}, headers={
                "Strict-Transport-Security": "max-age=63072000",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            })
            return
        if path == "/headers/insecure":
            self._send(200, {"ok": True})  # 一个安全头都没有
            return

        # CORS 检测对照点
        if path == "/cors/reflect":
            origin = self.headers.get("Origin", "")
            self._send(200, {"ok": True}, headers={
                "Access-Control-Allow-Origin": origin,           # 原样回显 → 脆弱
                "Access-Control-Allow-Credentials": "true",
            })
            return
        if path == "/cors/safe":
            self._send(200, {"ok": True}, headers={
                "Access-Control-Allow-Origin": "https://app.trusted.com",  # 固定可信域
            })
            return

        self._send(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_body()

        if path == "/auth/register":
            # 颁发 buyer 角色 token,响应结构对齐 scanner._register 的期望
            uid = uuid.uuid4().hex
            self._send(200, {
                "data": {
                    "tokens": {"access_token": f"tok-{uid}-buyer"},
                    "user": {"id": uid},
                }
            })
            return

        if path == "/graphql":
            # GRAPHQL-INTROSPECTION 探测点
            if "graphql_introspection" in self.vulns:
                self._send(200, {"data": {"__schema": {"types": [{"name": "User"}]}}})
            else:
                self._send(200, {"errors": [{"message": "introspection is disabled"}]})
            return

        if path == "/safe":
            # 健康对照(POST 路径,因为端点名不含 search/query/find)
            self._send(200, {"results": [], "ok": True})
            return

        if path == "/products":
            # 脆弱 POST: 同样的报错型反射
            if _looks_like_sqli(body):
                self._send(500, {"error": _SQL_ERROR})
                return
            self._send(200, {"results": []})
            return

        if path == "/account/update":
            # MASS-ASSIGNMENT 探测点
            try:
                payload = json.loads(body) if body else {}
            except ValueError:
                payload = {}
            if "mass_assignment" in self.vulns:
                # 脆弱: 把客户端传入的所有字段原样落库并回显(含特权字段)
                self._send(200, dict(payload))
            else:
                # 安全: 只接受白名单字段,忽略 role/is_admin/balance 等
                self._send(200, {"name": payload.get("name", "")})
            return

        if path == "/admin/thing":
            # OPS-ESCALATE 探测点: 默认仅 ops/admin 放行,开关打开则不校验角色
            role = _role_from_token(self._token())
            if "ops_escalation" in self.vulns or role in ("ops", "admin"):
                self._send(200, {"ok": True})
            else:
                self._send(403, {"error": "forbidden"})
            return

        # IDOR 探测点: scanner.scan_idor 打这两条固定路径(id 已被替换成占位值)
        if path.startswith("/users/me/notifications/") and path.endswith("/read"):
            self._send(200 if "idor" in self.vulns else 404, {"error": "not found"})
            return
        if path.startswith("/questions/") and path.endswith("/answer"):
            self._send(200 if "idor" in self.vulns else 404, {"error": "not found"})
            return

        self._send(404, {"error": "not found"})


class VulnerableServer:
    """在后台线程里跑靶机,绑定随机空闲端口。

    vulns: 启用哪几类漏洞({"auth_bypass","ops_escalation","idor"});默认全关。
    """

    def __init__(self, host: str = "127.0.0.1", vulns=frozenset()):
        self.host = host
        self._httpd = ThreadingHTTPServer((host, 0), _Handler)
        self._httpd.vulns = frozenset(vulns)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


if __name__ == "__main__":
    srv = VulnerableServer().start()
    print(f"靶机运行中: {srv.base_url} (Ctrl-C 停止)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
