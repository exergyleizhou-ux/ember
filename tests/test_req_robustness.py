"""
扫描器健壮性:_safe_json 容忍非 JSON 响应(真实目标的纯文本 404 / HTML 错误页
不该把扫描搞崩)。从对绿洲后端实扫中发现的 bug 回归。
"""


def test_safe_json_parses_dict(scanner_mod):
    assert scanner_mod._safe_json(b'{"a": 1}') == {"a": 1}


def test_safe_json_empty(scanner_mod):
    assert scanner_mod._safe_json(b"") == {}
    assert scanner_mod._safe_json(None) == {}


def test_safe_json_non_json_text_does_not_crash(scanner_mod):
    # gin 默认 404 是纯文本 "404 page not found" → 旧版 json.loads 会抛 "Extra data"
    out = scanner_mod._safe_json(b"404 page not found")
    assert out["_raw"] == "404 page not found"


def test_safe_json_non_dict_value_wrapped(scanner_mod):
    assert scanner_mod._safe_json(b"true") == {"_value": True}
    assert scanner_mod._safe_json(b"[1,2]") == {"_value": [1, 2]}


def test_req_returns_dict_on_non_json(scanner_mod, vuln_server):
    # 端到端:打一个不存在的路径(靶机返回 JSON 404),_req 返回 dict 不崩
    s = scanner_mod.Scanner(vuln_server.base_url)
    status, body, _ = s._req("GET", "/definitely-not-a-route")
    assert isinstance(body, dict)
