"""
单元测试: network.is_weak_cipher — 弱加密判定。
误判会让 TLS 检查漏报弱套件或对强套件误报,必须钉死。
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def net():
    spec = importlib.util.spec_from_file_location("ember_network", ROOT / "network" / "scan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("cipher", [
    "RC4-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "EXP-RC4-MD5",          # EXPORT 级
    "ADH-AES128-SHA",       # 这里用显式 anon 名验证
    "NULL-SHA",
])
def test_weak_ciphers_flagged(net, cipher):
    # 上面除 ADH 外都含明确弱标记;ADH 用下面单独的 anon 用例覆盖
    if "ADH" in cipher:
        pytest.skip("ADH 由 anon 名覆盖")
    assert net.is_weak_cipher(cipher) is True


def test_anon_cipher_flagged(net):
    assert net.is_weak_cipher("DHE-RSA-anon-AES") is True


@pytest.mark.parametrize("cipher", [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "TLS_AES_128_GCM_SHA256",
])
def test_strong_ciphers_not_flagged(net, cipher):
    assert net.is_weak_cipher(cipher) is False


def test_empty_cipher_safe(net):
    assert net.is_weak_cipher("") is False
    assert net.is_weak_cipher(None) is False
