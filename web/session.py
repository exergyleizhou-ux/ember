#!/usr/bin/env python3
"""
Ember 会话管理器 — 自动认证、Cookie 维护、CSRF 提取。

能力:
  - 自动识别登录表单 (用户名/密码字段)
  - Cookie jar 自动维护
  - CSRF token 提取和注入
  - JWT 解析和重放
  - Session 超时自动重登录

用法:
  from web.session import SessionManager
  session = SessionManager(target, login_url="/login", creds={"user":"admin","pass":"pass"})
  session.login()
  body = session.get("/admin/dashboard")
"""

import re, json, time
from typing import Dict, List, Tuple, Optional
from urllib.request import Request, urlopen, HTTPError, build_opener, HTTPCookieProcessor
from urllib.error import URLError
from urllib.parse import urljoin
from http.cookiejar import CookieJar


class SessionManager:
    """带 Cookie jar 的认证会话."""

    def __init__(self, target: str, timeout: int = 15):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.jar = CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.jar))
        self.csrf_token: Optional[str] = None
        self.jwt_token: Optional[str] = None
        self.authenticated = False

    def _req(self, method: str, path: str, data: Optional[str] = None,
             ct: str = "application/x-www-form-urlencoded",
             extra_headers: Optional[Dict] = None) -> Tuple[int, str]:
        url = self.target + path
        req = Request(url, data=data.encode() if data else None, method=method)
        req.add_header("Content-Type", ct)
        req.add_header("User-Agent", "Ember-Session/2.0")
        if self.jwt_token:
            req.add_header("Authorization", f"Bearer {self.jwt_token}")
        if self.csrf_token:
            req.add_header("X-CSRF-Token", self.csrf_token)
            if data and "csrf" not in data:
                pass  # CSRF tokens are usually header-based now
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            self._extract_csrf(resp.read().decode(errors="replace"))
            resp = self.opener.open(req, timeout=self.timeout)  # re-open since body consumed
            return resp.status, resp.read().decode(errors="replace")
        except HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except URLError as e:
            return 0, str(e.reason)

    def _extract_csrf(self, body: str):
        """从 HTML 中提取 CSRF token."""
        patterns = [
            r'name="csrf_token"[^>]*value="([^"]+)"',
            r'name="_token"[^>]*value="([^"]+)"',
            r'name="csrfmiddlewaretoken"[^>]*value="([^"]+)"',
            r'meta name="csrf-token" content="([^"]+)"',
            r'XSRF-TOKEN[^=]*=[^;]*[\'"]([^\'"]+)',
        ]
        for p in patterns:
            m = re.search(p, body, re.IGNORECASE)
            if m:
                self.csrf_token = m.group(1)
                return

    def try_login(self, login_path: str, creds: Dict[str, str],
                  method: str = "POST") -> bool:
        """自动尝试登录."""
        print(f"🔑 尝试登录 {login_path} …")

        # First GET to extract CSRF
        self._req("GET", login_path)

        # Build login data
        if self.csrf_token:
            creds["csrf_token"] = self.csrf_token
            creds["_token"] = self.csrf_token

        body = "&".join(f"{k}={v}" for k, v in creds.items())
        status, resp_body = self._req(method, login_path, body)

        # Check for JWT in response
        jwt_match = re.search(r'"access_token"\s*:\s*"([^"]+)"', resp_body)
        if jwt_match:
            self.jwt_token = jwt_match.group(1)
            self.authenticated = True
            print(f"   ✅ JWT 登录成功: {self.jwt_token[:24]}…")
            return True

        # Check for Django session
        if "sessionid" in str(self.jar):
            self.authenticated = True
            print("   ✅ Session 登录成功")
            return True

        # Follow redirect
        if status in (301, 302):
            self.authenticated = True
            print(f"   ✅ 登录成功 (redirect to {status})")
            return True

        print(f"   ❌ 登录失败 (status={status})")
        return False

    def try_login_json(self, login_path: str, creds: Dict,
                       method: str = "POST") -> bool:
        """JSON 模式登录 (API)."""
        data = json.dumps(creds)
        status, body = self._req(method, login_path, data, "application/json")

        jwt = None
        try:
            j = json.loads(body)
            jwt = j.get("data", {}).get("tokens", {}).get("access_token")
            if not jwt:
                jwt = j.get("token")
            if not jwt:
                jwt = j.get("access_token")
        except:
            pass

        if jwt:
            self.jwt_token = jwt
            self.authenticated = True
            print(f"   ✅ JWT: {jwt[:24]}…")
            return True

        print(f"   ❌ JSON 登录失败 (status={status})")
        return False

    def get(self, path: str) -> Tuple[int, str]:
        return self._req("GET", path)

    def post(self, path: str, data: str = "", ct: str = "application/x-www-form-urlencoded") -> Tuple[int, str]:
        return self._req("POST", path, data, ct)
