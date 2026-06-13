"""P3: SSRF 主动验证(OWASP API7)—— 带外(OOB)确认。

起一个本地受控 HTTP 监听器,把它的地址作为 SSRF 载荷发给目标;
若目标真的回连了这个地址,说明它替我们发起了请求 = 确认 SSRF。

局限(诚实声明):OOB 监听器在 127.0.0.1 上,要求目标能回连到扫描器主机。
同机/同网目标可用;打互联网目标需公网回连服务(如 Burp Collaborator),本工具不内置。
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from .base import Detector, register

# 常见的"服务端会去抓取"的参数名
SSRF_PARAMS = ("url", "uri", "callback", "webhook", "dest", "fetch", "image_url")


class _OobHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET


class OobListener:
    """受控带外监听器:记录是否被回连。"""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self._httpd = ThreadingHTTPServer((host, 0), _OobHandler)
        self._httpd.hits = []
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/oob"

    @property
    def hit(self) -> bool:
        return len(self._httpd.hits) > 0

    def clear(self):
        self._httpd.hits.clear()

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def _wait_hit(listener, timeout: float = 0.3) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if listener.hit:
            return True
        time.sleep(0.02)
    return listener.hit


@register
class SsrfDetector(Detector):
    name = "ssrf"
    owasp = "API7:2023"
    severity = "high"

    def run(self, ctx):
        endpoints = ctx.public + ctx.jwt
        print(f"\n🔍 SSRF: 打 {len(endpoints)} 个端点(带外回连验证)")
        listener = OobListener().start()
        token = getattr(ctx, "token", None) or ctx.buyer_token
        try:
            for ep in endpoints:
                base = ctx._resolve(ep["path"])
                found = False
                for param in SSRF_PARAMS:
                    listener.clear()
                    sep = "&" if "?" in base else "?"
                    path = f"{base}{sep}{param}={quote(listener.url, safe='')}"
                    ctx._req(ep["method"], path, token=token)
                    if _wait_hit(listener):
                        ctx.stats["total"] += 1
                        ctx._add("high", self.name, base, ep["method"],
                                 f"参数 {param} 触发服务端回连受控地址 → 确认 SSRF",
                                 evidence=listener.url)
                        found = True
                        break
                if not found:
                    ctx.stats["total"] += 1
                    ctx.stats["passed"] += 1
        finally:
            listener.stop()
