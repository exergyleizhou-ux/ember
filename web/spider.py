#!/usr/bin/env python3
"""
Ember Spider — 全自动化网站爬虫。

能力:
  1. 从首页出发,BFS 遍历所有 <a href>, <form>, <script src>
  2. 自动提取: URL 端点、表单参数、API 路径、JavaScript 文件中的路由
  3. 生成 OpenAPI 风格的端点清单供 scanner 使用
  4. 支持 SPA 应用 (检测 React Router / Next.js 路由模式)
  5. 自动去重、基域限制、深度控制

用法:
  python3 web/spider.py -t http://localhost:3000
  python3 web/spider.py -t http://localhost:3000 --depth 3 --output endpoints.json
"""

import re, json, time, sys, os
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.request import Request, urlopen, HTTPError
from urllib.error import URLError
from typing import List, Dict, Set, Tuple, Optional
from collections import deque
from html.parser import HTMLParser


class LinkExtractor(HTMLParser):
    """从 HTML 提取所有 actionable 元素."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self.scripts: List[str] = []
        self.api_calls: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attrs_d = dict(attrs)

        if tag == "a" and "href" in attrs_d:
            self.links.append(urljoin(self.base, attrs_d["href"]))

        elif tag == "form":
            action = attrs_d.get("action", "")
            method = attrs_d.get("method", "GET").upper()
            self.forms.append({"action": urljoin(self.base, action), "method": method})

        elif tag == "script" and "src" in attrs_d:
            self.scripts.append(urljoin(self.base, attrs_d["src"]))

        elif tag in ("button", "input") and "formaction" in attrs_d:
            self.links.append(urljoin(self.base, attrs_d["formaction"]))


class Spider:
    """BFS 爬虫 — 自动发现站点全部端点和参数."""

    def __init__(self, target: str, max_depth: int = 3, max_pages: int = 200,
                 timeout: int = 10, scope: Optional[str] = None):
        self.target = target.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.scope = scope or urlparse(target).netloc

        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Dict] = {}  # path -> {methods, forms, params}
        self.queue = deque()

        self.js_patterns = [
            # REST API patterns
            r'["\'](/api/[^"\'\s]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            # Next.js / React Router
            r'(?:href|to)=["\']([^"\']+)["\']',
            r'path:\s*["\']([^"\']+)["\']',
            r'route:\s*["\']([^"\']+)["\']',
            # WebSocket
            r'(?:ws|wss):\/\/[^"\'\s]+',
        ]
        self.discovered_params: Set[str] = set()

    def _fetch(self, url: str) -> Tuple[int, Optional[str], str]:
        """抓取 URL,返回 (status, html_body, content_type)."""
        try:
            req = Request(url, headers={"User-Agent": "Ember-Spider/2.0"})
            resp = urlopen(req, timeout=self.timeout)
            ct = resp.headers.get("Content-Type", "")
            body = resp.read().decode(errors="replace")
            return resp.status, body, ct
        except HTTPError as e:
            return e.code, None, ""
        except URLError:
            return 0, None, ""
        except Exception:
            return 0, None, ""

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.netloc:
            return True  # relative URL
        return parsed.netloc == self.scope

    def _register_endpoint(self, full_url: str, method: str = "GET"):
        parsed = urlparse(full_url)
        path = parsed.path or "/"
        params = parse_qs(parsed.query)

        if path not in self.endpoints:
            self.endpoints[path] = {"methods": set(), "params": set()}

        self.endpoints[path]["methods"].add(method)
        for k in params:
            self.endpoints[path]["params"].add(k)
            self.discovered_params.add(k)

    def _extract_js_endpoints(self, js_content: str):
        """从 JS 文件中提取 API 路由."""
        for pattern in self.js_patterns:
            for match in re.finditer(pattern, js_content):
                url_candidate = match.group(1)
                if url_candidate.startswith("/"):
                    full_url = urljoin(self.target, url_candidate)
                    self._register_endpoint(full_url)
                    # Also queue if in scope
                    if self._is_in_scope(full_url):
                        self.queue.append((full_url, 99))  # max depth for API endpoints

    def crawl(self) -> Dict:
        """执行完整 BFS 爬虫."""
        print(f"🕷️  Spider: {self.target} (max depth {self.max_depth}, max {self.max_pages} pages)")
        self.queue.append((self.target, 0))
        pages_crawled = 0

        while self.queue and pages_crawled < self.max_pages:
            url, depth = self.queue.popleft()

            if url in self.visited or depth > self.max_depth:
                continue
            if not self._is_in_scope(url):
                continue

            self.visited.add(url)
            pages_crawled += 1
            self._register_endpoint(url)

            status, body, ct = self._fetch(url)
            print(f"  [{status}] {url}" if status else f"  [ERR] {url}")

            if not body or status >= 400:
                continue

            # Parse HTML
            if "html" in ct or "text" in ct:
                parser = LinkExtractor(url)
                try:
                    parser.feed(body)
                except Exception:
                    pass

                # Register links
                for link in parser.links:
                    self._register_endpoint(link)
                    if link not in self.visited:
                        self.queue.append((link, depth + 1))

                # Register forms
                for form in parser.forms:
                    self._register_endpoint(form["action"], form["method"])

                # Fetch and analyze JS files
                for script in parser.scripts[:10]:  # cap JS files
                    if script in self.visited:
                        continue
                    self.visited.add(script)
                    _, js_body, _ = self._fetch(script)
                    if js_body:
                        self._extract_js_endpoints(js_body)

            # Pure JS/Python files
            elif "javascript" in ct or "python" in ct:
                self._extract_js_endpoints(body)

            time.sleep(0.1)  # polite crawling

        return self.report()

    def report(self) -> Dict:
        """生成爬虫报告."""
        endpoints = []
        for path, info in sorted(self.endpoints.items()):
            endpoints.append({
                "path": path,
                "methods": sorted(info["methods"]),
                "params": sorted(info["params"]) if info["params"] else [],
            })

        get_count = sum(1 for ep in endpoints if "GET" in ep["methods"])
        post_count = sum(1 for ep in endpoints if "POST" in ep["methods"])
        api_count = sum(1 for ep in endpoints if "/api/" in ep["path"] or "/rest/" in ep["path"])

        return {
            "target": self.target,
            "pages_crawled": len(self.visited),
            "endpoints_found": len(endpoints),
            "get_endpoints": get_count,
            "post_endpoints": post_count,
            "api_endpoints": api_count,
            "params_discovered": sorted(self.discovered_params),
            "endpoints": endpoints,
        }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ember Spider — 全自动爬虫")
    ap.add_argument("-t", "--target", required=True, help="目标 URL")
    ap.add_argument("-d", "--depth", type=int, default=3)
    ap.add_argument("--max-pages", type=int, default=200)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--scope", default=None, help="限制域名范围")
    args = ap.parse_args()

    spider = Spider(args.target, max_depth=args.depth, max_pages=args.max_pages, scope=args.scope)
    report = spider.crawl()

    print(f"\n{'═'*60}")
    print(f"爬虫完成: {report['pages_crawled']} 页, {report['endpoints_found']} 端点")
    print(f"  GET: {report['get_endpoints']}  POST: {report['post_endpoints']}  API: {report['api_endpoints']}")
    print(f"  参数: {', '.join(report['params_discovered'][:20])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"📄 报告: {args.output}")
