"""
单元测试: scanner.scope — 授权护栏。这是生产/法律层面的硬性要求,
必须钉死"未授权目标一定被拒、本机一定放行"。
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def scope():
    spec = importlib.util.spec_from_file_location("ember_scope", ROOT / "scanner" / "scope.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── target_host ──
@pytest.mark.parametrize("target,expected", [
    ("http://localhost:8080/api/v1", "localhost"),
    ("https://staging.example.com/x", "staging.example.com"),
    ("example.com:443", "example.com"),
    ("HTTP://Example.COM/", "example.com"),
    ("", ""),
])
def test_target_host(scope, target, expected):
    assert scope.target_host(target) == expected


# ── 本机始终放行 ──
@pytest.mark.parametrize("target", [
    "http://localhost:8080",
    "http://127.0.0.1:4280/api",
    "https://0.0.0.0",
])
def test_localhost_always_authorized(scope, target):
    assert scope.is_authorized(target, []) is True


# ── 非本机:需在 allowlist ──
def test_remote_denied_without_scope(scope):
    assert scope.is_authorized("https://prod.example.com", []) is False


def test_remote_allowed_exact_match(scope):
    assert scope.is_authorized("https://prod.example.com", ["prod.example.com"]) is True


def test_remote_allowed_as_subdomain(scope):
    # 授权 example.com 应覆盖其子域
    assert scope.is_authorized("https://api.example.com", ["example.com"]) is True


def test_subdomain_suffix_not_confused(scope):
    # notexample.com 不应被 example.com 授权命中
    assert scope.is_authorized("https://notexample.com", ["example.com"]) is False


# ── require_authorized 抛错 ──
def test_require_authorized_raises_for_remote(scope):
    with pytest.raises(scope.UnauthorizedTargetError):
        scope.require_authorized("https://prod.example.com", [])


def test_require_authorized_passes_for_local(scope):
    # 不应抛异常
    scope.require_authorized("http://localhost:9000", [])


def test_require_authorized_passes_when_scoped(scope):
    scope.require_authorized("https://prod.example.com", ["prod.example.com"])


# ── parse_scope ──
def test_parse_scope(scope):
    assert scope.parse_scope("a.com, b.com ,, c.com") == ["a.com", "b.com", "c.com"]
    assert scope.parse_scope("") == []
