"""单元测试: JWT 伪造工具(纯函数)。"""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def jf():
    spec = importlib.util.spec_from_file_location(
        "ember_jwt_forge", ROOT / "scanner" / "detectors" / "jwt_forge.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.fixture()
def valid_token():
    h = _b64u({"alg": "HS256", "typ": "JWT"})
    p = _b64u({"sub": "u1", "role": "user"})
    return f"{h}.{p}.originalsig"


def test_decode_parts(jf, valid_token):
    header, payload, sig = jf.decode_parts(valid_token)
    assert header["alg"] == "HS256"
    assert payload["role"] == "user"
    assert sig == "originalsig"


def test_forge_alg_none(jf, valid_token):
    forged = jf.forge_alg_none(valid_token)
    header, _, sig = jf.decode_parts(forged)   # "h.p." → sig 段为空字符串
    assert header["alg"] == "none"
    assert sig == ""


def test_forge_unsigned_keeps_alg_empties_sig(jf, valid_token):
    forged = jf.forge_unsigned(valid_token)
    header, _, sig = jf.decode_parts(forged)
    assert header["alg"] == "HS256"
    assert sig == ""


def test_forge_tampered_escalates_and_keeps_sig(jf, valid_token):
    forged = jf.forge_tampered(valid_token)
    _, payload, sig = jf.decode_parts(forged)
    assert payload["role"] == "admin"    # 提权
    assert sig == "originalsig"          # 保留原签名(测服务端是否真校验)
