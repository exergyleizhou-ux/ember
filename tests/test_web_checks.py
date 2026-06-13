"""
单元测试: scanner.web_checks — 安全头缺失 + CORS 判定。纯函数,无需服务器。
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def wc():
    spec = importlib.util.spec_from_file_location("ember_web_checks", ROOT / "scanner" / "web_checks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 安全头 ──
def test_all_headers_present_no_finding(wc):
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    assert wc.missing_security_headers(headers) == []


def test_all_headers_missing(wc):
    missing = wc.missing_security_headers({})
    names = {m[0] for m in missing}
    assert names == set(wc.SECURITY_HEADERS.keys())


def test_case_insensitive_header_names(wc):
    # 大小写不应影响"已存在"判定
    headers = {"STRICT-TRANSPORT-SECURITY": "x", "content-security-policy": "y",
               "X-Content-Type-Options": "nosniff", "x-frame-options": "DENY"}
    assert wc.missing_security_headers(headers) == []


def test_csp_frame_ancestors_covers_xfo(wc):
    # 有 CSP frame-ancestors 时,不再因缺 X-Frame-Options 报点击劫持
    headers = {
        "strict-transport-security": "x",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
    }
    names = {m[0] for m in wc.missing_security_headers(headers)}
    assert "x-frame-options" not in names


# ── CORS ──
def test_cors_reflects_arbitrary_origin(wc):
    res = wc.analyze_cors("https://evil.example", {
        "Access-Control-Allow-Origin": "https://evil.example",
    })
    assert res is not None
    assert res[1] == "medium"


def test_cors_reflect_with_credentials_is_high(wc):
    res = wc.analyze_cors("https://evil.example", {
        "Access-Control-Allow-Origin": "https://evil.example",
        "Access-Control-Allow-Credentials": "true",
    })
    assert res is not None
    assert res[1] == "high"


def test_cors_wildcard_with_credentials_is_high(wc):
    res = wc.analyze_cors("https://evil.example", {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    assert res is not None
    assert res[1] == "high"


def test_cors_safe_fixed_origin_no_finding(wc):
    # 只允许自己的域,不回显攻击者 Origin → 无问题
    res = wc.analyze_cors("https://evil.example", {
        "Access-Control-Allow-Origin": "https://app.trusted.com",
    })
    assert res is None


def test_cors_no_headers_no_finding(wc):
    assert wc.analyze_cors("https://evil.example", {}) is None
