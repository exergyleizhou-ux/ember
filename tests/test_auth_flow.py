"""
认证流自动取 token:单元(extract_token 纯函数)+ 集成(登录→取 token→喂 JWT 检测器)。
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def auth():
    spec = importlib.util.spec_from_file_location("ember_auth", ROOT / "scanner" / "auth.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── extract_token 纯函数 ──
def test_extract_by_explicit_path(auth):
    obj = {"data": {"tokens": {"access_token": "a.b.c"}}}
    assert auth.extract_token(obj, "data.tokens.access_token") == "a.b.c"


def test_extract_missing_path_returns_none(auth):
    assert auth.extract_token({"data": {}}, "data.tokens.access_token") is None


def test_auto_detect_prefers_jwt_shaped(auth):
    # 两个常见字段:auto 应取 JWT 形状(含两个点)的那个
    obj = {"token": "opaque", "nested": {"access_token": "h.p.s"}}
    assert auth.extract_token(obj) == "h.p.s"


def test_auto_detect_falls_back_to_any_common_key(auth):
    obj = {"data": {"token": "opaque-session-id"}}
    assert auth.extract_token(obj) == "opaque-session-id"


def test_auto_detect_none_when_absent(auth):
    assert auth.extract_token({"user": {"id": 1}}) is None


# ── 集成: 登录 → token → JWT 检测器端到端 ──
def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def test_login_flow_feeds_jwt_detector(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"jwt_alg_none"})
    scanner = scanner_mod.Scanner(server.base_url)
    # 自动取 token(显式路径)
    tok = scanner.acquire_token("/auth/login", {"account": "x", "password": "y"},
                                token_path="data.tokens.access_token")
    assert tok and tok.count(".") == 2, "应从登录响应提取到 JWT"
    assert scanner.token == tok

    scanner.jwt = [{"path": "/jwt/protected", "method": "GET"}]
    detectors_mod.get("jwt-alg-none").run(scanner)
    assert _findings(scanner, "jwt-alg-none"), "登录取到的 token 应让 JWT 检测器跑起来并检出"


def test_login_flow_auto_detect_token(scanner_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    # 不给 path,自动发现
    tok = scanner.acquire_token("/auth/login", {"account": "x", "password": "y"})
    assert tok and tok.count(".") == 2, "应能自动发现嵌套的 access_token"
