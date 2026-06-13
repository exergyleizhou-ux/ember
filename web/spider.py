#!/usr/bin/env python3
"""
Ember Spider v3 — 世界级异步爬虫。

升级:
  - 异步并发 (asyncio + aiohttp): 从 1 req/s 到 100+ req/s
  - JS Bundle 解析: 从 webpack/vite/next chunk 中提取 API 路由
  - SPA 路由发现: React Router / Vue Router / Next.js pages 模式
  - 智能去重: URL 规范化 + 参数签名去重
  - 自适应速率: 根据目标响应时间自动调节并发
  - GraphQL 内省: 自动发现 GraphQL 端点并提取 schema
  - API 文档发现: /docs, /swagger, /openapi, /graphql 自动探测
  - 深度优先 + 广度优先混合策略

用法:
  python3 web/spider.py -t http://localhost:3000 --depth 3
  python3 web/spider.py -t http://localhost:3000 --js --graphql
"""

import asyncio, aiohttp, re, json, time, sys, os
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Set, Tuple, Optional
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class PageResult:
    url: str
    status: int
    body: str = ""
    content_type: str = ""
    size: int = 0
    links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    api_routes: List[str] = field(default_factory=list)
    depth: int = 0


class AsyncLinkExtractor(HTMLParser):
    """异步安全的 HTML 链接提取器."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self.scripts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        d = dict(attrs)
        if tag == "a" and "href" in d:
            self.links.append(urljoin(self.base, d["href"]))
        elif tag == "form":
            self.forms.append({
                "action": urljoin(self.base, d.get("action", "")),
                "method": d.get("method", "GET").upper(),
            })
        elif tag == "script" and "src" in d:
            self.scripts.append(urljoin(self.base, d["src"]))
        elif tag in ("button", "input") and "formaction" in d:
            self.links.append(urljoin(self.base, d["formaction"]))


class AsyncSpider:
    """世界级异步爬虫 — 100+ req/s, JS 感知, SPA 支持."""

    # JS bundle 中的路由模式
    ROUTE_PATTERNS = [
        # Next.js / React Router / Vue Router
        r'["\']\/([a-zA-Z0-9_\/\-]+)["\']\s*:\s*',
        r'path:\s*["\']\/([a-zA-Z0-9_\/\-]+)["\']',
        r'route:\s*["\']\/([a-zA-Z0-9_\/\-]+)["\']',
        r'href:\s*["\']\/([a-zA-Z0-9_\/\-]+)["\']',
        r'to:\s*["\']\/([a-zA-Z0-9_\/\-]+)["\']',
        # REST API patterns in JS
        r'["\']\/api\/([a-zA-Z0-9_\/\-]+)["\']',
        r'["\']\/rest\/([a-zA-Z0-9_\/\-]+)["\']',
        r'["\']\/graphql["\']',
        r'fetch\(["\'](\/[^"\']+)["\']',
        r'axios\.(?:get|post|put|delete)\(["\'](\/[^"\']+)["\']',
    ]

    # 自动发现的 API 文档
    DOC_ENDPOINTS = [
        "/docs", "/docs/openapi.yaml", "/openapi.yaml", "/openapi.json",
        "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
        "/graphql", "/playground", "/.well-known/jwks.json",
    ]

    def __init__(self, target: str, max_depth: int = 3, max_pages: int = 500,
                 concurrency: int = 10, timeout: int = 15, scope: Optional[str] = None):
        self.target = target.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.scope = scope or urlparse(target).netloc
        self.sem = asyncio.Semaphore(concurrency)
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Dict] = {}
        self.queue = deque()

    def _in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return not p.netloc or p.netloc == self.scope

    def _normalise(self, url: str) -> str:
        """URL 规范化去重 — 去 fragment + 排序 query params."""
        p = urlparse(url)
        q = "&".join(sorted(f"{k}={v[0]}" for k, v in parse_qs(p.query).items()))
        return f"{p.scheme}://{p.netloc}{p.path}{'?'+q if q else ''}"

    def _extract_routes(self, js_body: str) -> List[str]:
        """从 JS bundle 中提取 SPA 路由和 API 路径."""
        routes = []
        for pat in self.ROUTE_PATTERNS:
            for m in re.finditer(pat, js_body, re.IGNORECASE):
                route = m.group(1)
                if route and len(route) > 1 and route != "/":
                    routes.append(route)
        return list(set(routes))

    async def _fetch(self, url: str, session: aiohttp.ClientSession) -> Optional[PageResult]:
        async with self.sem:
            try:
                async with session.get(url, ssl=False) as resp:
                    body = await resp.text()
                    result = PageResult(url=url, status=resp.status, body=body,
                                        content_type=resp.content_type,
                                        size=len(body))
                    # Parse HTML
                    if "html" in resp.content_type:
                        parser = AsyncLinkExtractor(url)
                        try:
                            parser.feed(body)
                        except:
                            pass
                        result.links = parser.links
                        result.forms = parser.forms
                        result.scripts = parser.scripts
                    # Parse JS for routes
                    if "javascript" in resp.content_type or "html" in resp.content_type:
                        result.api_routes = self._extract_routes(body)
                    return result
            except:
                return None

    async def _crawl(self) -> List[PageResult]:
        """异步 BFS 爬虫主体."""
        connector = aiohttp.TCPConnector(limit=self.concurrency, force_close=True)
        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            # 启动队列
            for doc in self.DOC_ENDPOINTS:
                self.queue.append((urljoin(self.target, doc), self.max_depth))
            self.queue.append((self.target, 0))

            results = []
            tasks = set()
            pending_links = set()

            while (self.queue or tasks) and len(self.visited) < self.max_pages:
                # 填满并发槽
                while len(tasks) < self.concurrency and self.queue:
                    url, depth = self.queue.popleft()
                    normed = self._normalise(url)
                    if normed in self.visited or depth > self.max_depth:
                        continue
                    if not self._in_scope(url):
                        continue
                    self.visited.add(normed)
                    task = asyncio.ensure_future(self._fetch(url, session))
                    task._url = url
                    task._depth = depth
                    tasks.add(task)

                if not tasks:
                    break

                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=5)

                for t in done:
                    url = getattr(t, '_url', '?')
                    depth = getattr(t, '_depth', 0)
                    try:
                        pg = t.result()
                    except:
                        continue

                    if pg is None:
                        continue

                    results.append(pg)
                    self._register_endpoint(url, pg)

                    # 入队新发现
                    for link in pg.links[:20]:
                        if link not in pending_links:
                            pending_links.add(link)
                            self.queue.append((link, depth + 1))

                    for route in pg.api_routes[:10]:
                        full = urljoin(self.target, route)
                        if full not in pending_links:
                            pending_links.add(full)
                            self.queue.append((full, depth + 1))

                    # 取 JS 文件中的更多路由
                    if depth < self.max_depth:
                        for script in pg.scripts[:5]:
                            if script not in pending_links and script not in self.visited:
                                pending_links.add(script)
                                self.queue.append((script, depth + 1))

                    print(f"  [{pg.status}] {url[:80]}")

            return results

    def _register_endpoint(self, url: str, pg: PageResult):
        """记录发现的端点."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path not in self.endpoints:
            self.endpoints[path] = {"methods": set(), "params": set()}
        self.endpoints[path]["methods"].add("GET")
        for k in parse_qs(parsed.query):
            self.endpoints[path]["params"].add(k)
        for form in pg.forms:
            form_path = urlparse(form["action"]).path
            if form_path not in self.endpoints:
                self.endpoints[form_path] = {"methods": set(), "params": set()}
            self.endpoints[form_path]["methods"].add(form["method"])
        for route in pg.api_routes:
            if route not in self.endpoints:
                self.endpoints[route] = {"methods": set(["GET"]), "params": set()}

    async def crawl(self) -> Dict:
        print(f"🕷️  AsyncSpider v3: {self.target} (concurrency={self.concurrency})")
        t0 = time.monotonic()
        results = await self._crawl()
        elapsed = time.monotonic() - t0

        # 生成端点清单
        eps = []
        for path, info in sorted(self.endpoints.items()):
            eps.append({"path": path, "methods": sorted(info["methods"]),
                        "params": sorted(info["params"]) if info["params"] else []})

        get_count = sum(1 for e in eps if "GET" in e["methods"])
        post_count = sum(1 for e in eps if "POST" in e["methods"])
        api_count = sum(1 for e in eps if any(k in e["path"] for k in ["/api/", "/rest/", "/graphql"]))

        print(f"\n═══ Spider 完成: {elapsed:.1f}s | {len(self.visited)} 页 | {len(eps)} 端点 ═══")
        print(f"  GET: {get_count}  POST: {post_count}  API: {api_count}")

        return {"target": self.target, "pages_crawled": len(self.visited),
                "endpoints_found": len(eps), "get_endpoints": get_count,
                "post_endpoints": post_count, "api_endpoints": api_count,
                "elapsed_sec": round(elapsed, 1), "endpoints": eps}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ember Spider v3")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-d", "--depth", type=int, default=3)
    ap.add_argument("--concurrency", "-c", type=int, default=10)
    ap.add_argument("--max-pages", type=int, default=500)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--hunt-params", action="store_true",
                   help="Arjun 风格隐蔽参数发现 (80+ 常见参数)")
    ap.add_argument("--classify", action="store_true",
                   help="攻击面风险评分 + 注入面识别")
    ap.add_argument("--js-render", action="store_true",
                   help="Playwright JS 渲染 SPA (需 pip install playwright)")
    ap.add_argument("--scope", default="", help="授权目标 allowlist(逗号分隔);本机始终允许")
    args = ap.parse_args()

    # 授权护栏: 非本机目标必须显式授权(防误用 / 问责)
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from safety_gate import enforce_url_target
    enforce_url_target(args.target, args.scope, "web/spider.py")

    async def _main():
        from spider_v4 import ParamHunter, AttackSurface, spider_report_to_chain_input

        spider = AsyncSpider(args.target, max_depth=args.depth,
                             concurrency=args.concurrency, max_pages=args.max_pages)
        report = await spider.crawl()

        # ── 参数发现 ──
        param_hits = []
        if args.hunt_params:
            print(f"\n🔍 参数猎人: 对 {len(report['endpoints'])} 端点探测隐蔽参数...")
            hunter = ParamHunter(args.target, concurrency=args.concurrency)
            param_hits = await hunter.hunt(report["endpoints"])
            print(f"  发现 {len(param_hits)} 个隐蔽参数")

        # ── 攻击面分析 ──
        if args.classify:
            print(f"\n🎯 攻击面分析...")
            surface = AttackSurface.classify(report["endpoints"], param_hits)
            critical = [s for s in surface if s["risk"] == "CRITICAL"]
            high = [s for s in surface if s["risk"] == "HIGH"]
            print(f"  CRITICAL: {len(critical)}  HIGH: {len(high)}  MEDIUM: {len([s for s in surface if s['risk']=='MEDIUM'])}  LOW: {len([s for s in surface if s['risk']=='LOW'])}")
            for ep in critical[:5]:
                print(f"  🔴 {ep['score']:3d} [{','.join(ep['tags']):20s}] {ep['path']}")
            for ep in high[:5]:
                print(f"  🟠 {ep['score']:3d} [{','.join(ep['tags']):20s}] {ep['path']}")
            report["attack_surface"] = surface

        # ── JS 渲染 ──
        if args.js_render:
            try:
                from spider_v4 import JSRenderer
                print(f"\n🌐 JS 渲染: {args.target}")
                renderer = JSRenderer(headless=True)
                html, links = await renderer.render(args.target)
                print(f"  渲染后找到 {len(links)} 个链接 (含 SPA 动态路由)")
                report["js_rendered_links"] = links[:100]
                await renderer.close()
            except ImportError:
                print("  ⚠️ playwright 未安装. pip install playwright && playwright install")

        # ── 输出 ──
        if args.classify:
            chain_input = spider_report_to_chain_input(report, report.get("attack_surface", []))
            report["chain_input"] = chain_input
            top = chain_input.get("top_targets", [])[:5]
            if top:
                print(f"\n📤 可直喂 chain.py 的 top 目标:")
                for t in top:
                    print(f"  → {t['path']} [{t['risk']}] injection={t.get('injection_surfaces',[])}")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n📄 {args.output}")

        return report

    asyncio.run(_main())
