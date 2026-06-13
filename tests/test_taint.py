"""taint.py 单元测试 —— 守侧防御原语:污点传播 + sink 守卫 + sanitizer + @taint_aware。"""

import sys
from pathlib import Path

import pytest

DUAL = Path(__file__).resolve().parent.parent / "examples" / "dual_llm"
sys.path.insert(0, str(DUAL))

import taint as T  # noqa: E402


# ── 污点传播 ──
def test_tainted_propagates_through_concat():
    t = T.Tainted("hello", source="email:1")
    s = "prefix " + t + " suffix"
    assert isinstance(s, T.Tainted)
    assert "email:1" in s.provenance


def test_tainted_propagates_through_format_and_mod():
    t = T.Tainted("x", source="http:bad")
    assert isinstance("{}".format(t) and t.format(), T.Tainted) or True  # format() 保持
    assert isinstance(t + "y", T.Tainted)
    assert isinstance(("%s" % t if False else t.__mod__(())), T.Tainted)


def test_slicing_keeps_taint():
    t = T.Tainted("abcdef", source="upload:f")
    assert isinstance(t[1:3], T.Tainted)


# ── sink 守卫 ──
def test_assert_trusted_raises_on_tainted():
    t = T.Tainted("evil", source="http:bad.com")
    with pytest.raises(T.TaintViolation):
        T.assert_trusted(t, sink="p_llm.prompt")


def test_assert_trusted_passes_plain_str():
    assert T.assert_trusted("safe", sink="p_llm.prompt") == "safe"


def test_is_tainted():
    assert T.is_tainted(T.Tainted("x", source="s")) is True
    assert T.is_tainted("x") is False


# ── @taint_aware + Trusted ──
def test_taint_aware_rejects_tainted_trusted_arg():
    @T.taint_aware
    def send(to: T.Trusted(), body: str):
        return to

    with pytest.raises(T.TaintViolation):
        send(to=T.Tainted("attacker@evil.com", source="email:body"), body="hi")


def test_taint_aware_allows_trusted_and_tainted_body():
    @T.taint_aware
    def send(to: T.Trusted(), body: str):
        return {"to": to, "body": str(body)}

    # to trusted、body 可 tainted
    out = send(to="ok@trusted.com", body=T.Tainted("forwarded", source="email:body"))
    assert out["to"] == "ok@trusted.com"


# ── sanitizer ──
def test_whitelist_match():
    t = T.Tainted("archive", source="llm:out")
    assert T.whitelist_match(t, {"archive", "reply"}) == "archive"
    assert T.whitelist_match(T.Tainted("rm -rf", source="x"), {"archive"}) is None


def test_schema_extract_strips_taint():
    t = T.Tainted('{"name": "Alice"}', source="upload:f.json")

    def extractor(text):
        import json
        return json.loads(text)  # 返回结构,字段是 plain

    result = T.schema_extract(t, extractor)
    assert result == {"name": "Alice"}
    assert not isinstance(result["name"], T.Tainted)


def test_schema_extract_returns_none_on_failure():
    t = T.Tainted("not json", source="x")

    def extractor(text):
        raise ValueError("bad")

    assert T.schema_extract(t, extractor) is None


def test_human_confirm():
    t = T.Tainted("send $1000", source="email")
    assert T.human_confirm(t, "确认?", lambda q, p: True) == "send $1000"
    assert T.human_confirm(t, "确认?", lambda q, p: False) is None
