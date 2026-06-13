"""
P4 接口暴露检测器:单元(纯判定)+ 集成(经注册表打靶机)。
覆盖 graphql-introspection / debug-exposure / http-method / verbose-errors。
"""

import pytest


@pytest.fixture(scope="module")
def ex(detectors_mod):
    return detectors_mod.exposure


# ── 纯函数 ──
def test_is_introspection_enabled(ex):
    assert ex.is_introspection_enabled('{"data":{"__schema":{"types":[]}}}') is True
    assert ex.is_introspection_enabled('{"errors":["disabled"]}') is False


@pytest.mark.parametrize("body,expected", [
    ('Traceback (most recent call last):\n  File "/app/x.py", line 1', True),
    ('at com.example.Foo(Foo.java:42)', True),
    ('goroutine 1 [running]:', True),
    ('{"error":"bad request"}', False),
])
def test_is_verbose_error(ex, body, expected):
    assert ex.is_verbose_error(body) is expected


# ── 集成 ──
def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def test_graphql_introspection_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"graphql_introspection"})
    scanner = scanner_mod.Scanner(server.base_url)
    detectors_mod.get("graphql-introspection").run(scanner)
    assert _findings(scanner, "graphql-introspection"), "introspection 开启未被检出"


def test_graphql_introspection_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    detectors_mod.get("graphql-introspection").run(scanner)
    assert not _findings(scanner, "graphql-introspection"), "禁用 introspection 被误报"


def test_debug_exposure_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"debug_exposure"})
    scanner = scanner_mod.Scanner(server.base_url)
    detectors_mod.get("debug-exposure").run(scanner)
    assert _findings(scanner, "debug-exposure"), "暴露的 /openapi.json 未被检出"


def test_debug_exposure_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    detectors_mod.get("debug-exposure").run(scanner)
    assert not _findings(scanner, "debug-exposure"), "404 的调试路径被误报"


def test_http_method_tampering_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"trace_method"})
    scanner = scanner_mod.Scanner(server.base_url)
    detectors_mod.get("http-method").run(scanner)
    assert _findings(scanner, "http-method"), "TRACE 回显未被检出"


def test_http_method_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    detectors_mod.get("http-method").run(scanner)
    assert not _findings(scanner, "http-method"), "405 的 TRACE 被误报"


def test_verbose_errors_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"verbose_errors"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/error", "method": "GET"}]
    detectors_mod.get("verbose-errors").run(scanner)
    assert _findings(scanner, "verbose-errors"), "栈泄露未被检出"


def test_verbose_errors_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/error", "method": "GET"}]
    detectors_mod.get("verbose-errors").run(scanner)
    assert not _findings(scanner, "verbose-errors"), "通用报错被误报为栈泄露"
