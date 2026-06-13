#!/usr/bin/env python3
"""
Ember Spider v4 — 参数发现 + 攻击面识别 引擎

新增:
  ParamHunter — Arjun 风格隐藏参数暴力发现
  AttackSurface — 端点风险评分 + 注入面识别
  JS_Renderer — Playwright 可选 JS 渲染 (SPA 爬取)

依赖:
  pip install aiohttp playwright (可选: pip install playwright && playwright install)

用法:
  python3 web/spider.py -t http://localhost:3000 --hunt-params --classify
  python3 web/spider.py -t http://localhost:3000 --js-render  # 需要 playwright
"""

import asyncio, aiohttp, re, json, time, sys, os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import deque, defaultdict
from dataclasses import dataclass, field
from html.parser import HTMLParser
from hashlib import md5

# ═══════════════════════════════════════════════════════════════════════
# PARAM HUNTER — Arjun 风格隐蔽参数暴力发现
# ═══════════════════════════════════════════════════════════════════════

# 从 Arjun + PayloadsAllTheThings + 实战经验精选的参数字典
PARAM_DICT = [
    # ── 通用注入面 ──
    "id", "uid", "user", "username", "user_id", "name", "email", "password",
    "search", "query", "q", "keyword", "filter", "sort", "order", "dir",
    "page", "limit", "offset", "size", "start", "end", "from", "to",
    "token", "auth", "key", "api_key", "access_token", "session",
    # ── 文件操作 ──
    "file", "path", "filename", "dir", "url", "src", "dest", "target",
    "download", "upload", "image", "img", "doc", "document",
    # ── 注入专用 ──
    "cmd", "command", "exec", "action", "do", "func", "method", "callback",
    "redirect", "next", "return", "return_url", "redirect_uri",
    "debug", "test", "preview", "admin", "root",
    # ── SQL 注入面 ──
    "cat", "category", "type", "status", "role", "group", "level",
    "product_id", "order_id", "item_id", "post_id", "comment_id",
    # ── 模板/SSTI ──
    "template", "view", "layout", "format", "lang", "locale",
    # ── 内容注入 ──
    "message", "msg", "body", "content", "text", "description", "title",
    "subject", "comment", "review", "reply",
]


@dataclass
class ParamResult:
    endpoint: str
    method: str
    param: str
    status: int
    size_diff: int
    reflection: bool = False


class ParamHunter:
    """Arjun 风格隐蔽参数猎人。

    原理:
      - 对每个端点用常见参数发送请求
      - 比较响应大小/状态码/内容差异
      - 检测参数是否被反射 (反射 = 可能有 XSS)
    """

    COMMON_PARAMS = PARAM_DICT[:80]  # 前80个最高命中率

    def __init__(self, target: str, concurrency: int = 10, timeout: int = 10):
        self.target = target.rstrip("/")
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.sem = asyncio.Semaphore(concurrency)
        self.baselines: Dict[str, Dict] = {}  # endpoint -> baseline response

    async def _get_baseline(self, endpoint: str, method: str, session: aiohttp.ClientSession) -> Dict:
        """获取无参数时的基线响应."""
        try:
            async with session.request(method, urljoin(self.target, endpoint), ssl=False) as resp:
                body = await resp.text()
                return {"status": resp.status, "size": len(body), "body_hash": md5(body.encode()).hexdigest()}
        except:
            return {"status": 0, "size": 0, "body_hash": ""}

    async def _probe(self, endpoint: str, method: str, param: str,
                     session: aiohttp.ClientSession, baseline: Dict) -> Optional[ParamResult]:
        """探测单个参数."""
        async with self.sem:
            try:
                if method == "GET":
                    url = f"{urljoin(self.target, endpoint)}?{param}=EMBER_PROBE_42"
                    resp = await session.get(url, ssl=False)
                else:  # POST
                    resp = await session.post(
                        urljoin(self.target, endpoint),
                        data={param: "EMBER_PROBE_42"},
                        ssl=False,
                    )
                body = await resp.text()
                status = resp.status
                size = len(body)

                # 检测反射
                reflection = "EMBER_PROBE_42" in body

                # 差异分析
                size_diff = size - baseline["size"]
                status_diff = status != baseline["status"]

                if status_diff or abs(size_diff) > 50 or reflection:
                    return ParamResult(endpoint=endpoint, method=method, param=param,
                                       status=status, size_diff=size_diff, reflection=reflection)
                return None
            except:
                return None

    async def hunt(self, endpoints: List[Dict], session: aiohttp.ClientSession = None) -> List[ParamResult]:
        """对一批端点进行参数发现."""
        async def _run():
            connector = aiohttp.TCPConnector(limit=self.concurrency, force_close=True)
            async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as s:
                discoveries = []

                for ep in endpoints:
                    path = ep.get("path", "")
                    methods = ep.get("methods", ["GET"])
                    for method in methods:
                        if method not in ("GET", "POST"):
                            continue
                        # 基线
                        baseline = await self._get_baseline(path, method, s)
                        self.baselines[f"{method}:{path}"] = baseline

                        if baseline["status"] == 0:
                            continue

                        # 批量探测
                        tasks = []
                        for param in self.COMMON_PARAMS:
                            tasks.append(self._probe(path, method, param, s, baseline))

                        results = await asyncio.gather(*tasks)
                        for r in results:
                            if r:
                                discoveries.append(r)
                                print(f"  🔍 参数发现: [{method}] {path} ?{r.param}=  (diff={r.size_diff:+d}, refl={r.reflection})")

                return discoveries

        if session:
            return await self._hunt_with_session(endpoints, session)
        return await _run()

    async def _hunt_with_session(self, endpoints: List[Dict], session) -> List[ParamResult]:
        discoveries = []
        for ep in endpoints:
            path = ep.get("path", "")
            methods = ep.get("methods", ["GET"])
            for method in methods:
                if method not in ("GET", "POST"):
                    continue
                baseline = await self._get_baseline(path, method, session)
                self.baselines[f"{method}:{path}"] = baseline
                if baseline["status"] == 0:
                    continue

                tasks = [self._probe(path, method, param, session, baseline) for param in self.COMMON_PARAMS]
                results = await asyncio.gather(*tasks)
                for r in results:
                    if r:
                        discoveries.append(r)
                        print(f"  🔍 参数发现: [{method}] {path} ?{r.param}=  (diff={r.size_diff:+d}, refl={r.reflection})")
        return discoveries


# ═══════════════════════════════════════════════════════════════════════
# ATTACK SURFACE ANALYZER — 端点风险评分
# ═══════════════════════════════════════════════════════════════════════

class AttackSurface:
    """端点攻击面识别器。

    对每个端点评估:
      - 注入潜力 (参数存在/可猜解)
      - 认证需求 (是否有 auth guard)
      - WAF 指纹 (响应头)
      - 优先级排名 (高→中→低)
    """

    # 高危路径模式
    HIGH_RISK_PATTERNS = [
        (r'(login|signin|auth|oauth|sso)', 'AUTH', '认证入口'),
        (r'(admin|dashboard|manage|config|setting)', 'ADMIN', '管理后台'),
        (r'(api|rest|graphql|rpc)', 'API', 'API 端点'),
        (r'(upload|file|download|import|export)', 'FILE', '文件操作'),
        (r'(search|query|filter|find)', 'SEARCH', '搜索/查询'),
        (r'(payment|checkout|billing|order)', 'PAYMENT', '支付'),
        (r'(debug|test|dev|staging)', 'DEBUG', '调试/测试'),
        (r'(user|profile|account|password|reset)', 'USER', '用户数据'),
    ]

    # WAF 指纹 header
    WAF_HEADERS = [
        ('X-CDN', 'CDN'),
        ('Server', None),  # 任何 Server 头都看
        ('X-Powered-By', None),
        ('X-Frame-Options', None),
        ('Content-Security-Policy', None),
        ('X-Content-Type-Options', None),
        ('Strict-Transport-Security', None),
    ]

    @staticmethod
    def classify(endpoints: List[Dict], param_hits: List[ParamResult] = None) -> List[Dict]:
        """对端点列表进行攻击面分类."""
        param_set = set()
        if param_hits:
            for p in param_hits:
                param_set.add((p.endpoint, p.param, p.reflection))

        scored = []
        for ep in endpoints:
            path = ep.get("path", "/")
            methods = ep.get("methods", ["GET"])
            params = ep.get("params", [])
            status = ep.get("status", 0)

            # ── 风险评分 ──
            score = 0
            tags = []

            # 路径模式匹配
            for pat, tag, desc in AttackSurface.HIGH_RISK_PATTERNS:
                if re.search(pat, path, re.IGNORECASE):
                    score += 15
                    tags.append(tag)

            # 方法加分
            if "POST" in methods:
                score += 10
            if "PUT" in methods or "DELETE" in methods or "PATCH" in methods:
                score += 8

            # 参数存在加分
            if params:
                score += 5
                tags.append("HAS_PARAMS")

            # 已发现隐蔽参数加分
            hidden = [p for p, r in param_set if p == path]
            if hidden:
                score += 20
                tags.append("HIDDEN_PARAMS")

            # 状态码异常
            if status in (200, 302):
                score += 3
            elif status in (401, 403):
                score += 8  # 有认证但可达
                tags.append("AUTH_GATED")
            elif status >= 500:
                score += 12  # 错误可能泄露信息
                tags.append("ERROR_LEAK")

            # 等级
            if score >= 40:
                risk = "CRITICAL"
            elif score >= 25:
                risk = "HIGH"
            elif score >= 15:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            # ── 注入面判断 ──
            injection = []
            if any(k in path.lower() for k in ("search", "query", "q", "filter", "find")):
                injection.append("SQLi")
            if any(k in path.lower() for k in ("upload", "file", "img", "image", "download")):
                injection.append("FILE_UPLOAD")
            if any(k in path.lower() for k in ("login", "signin", "auth", "password")):
                injection.append("AUTH_BYPASS")
            if any(k in path.lower() for k in ("template", "view", "render", "layout")):
                injection.append("SSTI")
            if "POST" in methods and not params:
                injection.append("PARAM_DISCOVERY")

            scored.append({
                "path": path,
                "methods": methods,
                "params": params,
                "risk": risk,
                "score": score,
                "tags": tags,
                "injection_surfaces": injection,
                "hidden_params": hidden,
            })

        # 按风险排序
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored


# ═══════════════════════════════════════════════════════════════════════
# JS RENDERER (可选 — 需要 playwright)
# ═══════════════════════════════════════════════════════════════════════

class JSRenderer:
    """Playwright JS 渲染引擎 — 爬取动态 SPA."""

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._browser = None

    async def _ensure_browser(self):
        if self._browser is None:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=self.headless)

    async def render(self, url: str, wait_ms: int = 3000) -> Tuple[str, List[str]]:
        """渲染一个页面，返回HTML + 所有链接."""
        await self._ensure_browser()
        page = await self._browser.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(wait_ms / 1000.0)

            # 获取最终渲染后的链接
            links = await page.evaluate("""
                () => {
                    const links = new Set();
                    // 所有 a 标签
                    document.querySelectorAll('a[href]').forEach(a => links.add(a.href));
                    // Vue/React Router links
                    document.querySelectorAll('[to]').forEach(el => links.add(el.getAttribute('to')));
                    // 按钮
                    document.querySelectorAll('[data-url], [data-href]').forEach(el => {
                        links.add(el.getAttribute('data-url') || el.getAttribute('data-href'));
                    });
                    return Array.from(links);
                }
            """)

            html = await page.content()
            return html, links
        finally:
            await page.close()

    async def close(self):
        if self._browser:
            await self._browser.close()
            if hasattr(self, '_pw'):
                await self._pw.stop()


# ═══════════════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════════════

def spider_report_to_chain_input(spider_report: Dict, attack_surface: List[Dict]) -> Dict:
    """把 spider 结果转成 chain.py 可用格式."""
    return {
        "target": spider_report.get("target", ""),
        "stats": {
            "pages": spider_report.get("pages_crawled", 0),
            "endpoints": spider_report.get("endpoints_found", 0),
            "api_endpoints": spider_report.get("api_endpoints", 0),
        },
        "attack_surface": attack_surface,
        "top_targets": [ep for ep in attack_surface[:10] if ep["risk"] in ("CRITICAL", "HIGH")],
        "all_endpoints": spider_report.get("endpoints", []),
    }
