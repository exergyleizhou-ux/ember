"""
open-redirect + host-header 检测器:单元(纯判定)+ 集成(经注册表打靶机)。
"""

import pytest


@pytest.fixture(scope="module")
def rd(detectors_mod):
    return detectors_mod.redirect


# ── 纯函数 ──
def test_is_open_redirect_true(rd):
    assert rd.is_open_redirect("evil.example", "https://evil.example/x") is True
    assert rd.is_open_redirect("evil.example", "//evil.example/x") is True


def test_is_open_redirect_false_for_same_site(rd):
    assert rd.is_open_redirect("evil.example", "/dashboard") is False
    assert rd.is_open_redirect("evil.example", "https://app.trusted.com/x") is False


def test_reflects_host_in_body(rd):
    assert rd.reflects_host("evil.example", '{"link":"https://evil.example/r"}', "") is True


def test_reflects_host_false_when_fixed(rd):
    assert rd.reflects_host("evil.example", '{"link":"https://trusted.com/r"}', "") is False


# ── 集成 ──
def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def test_open_redirect_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"open_redirect"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/redirect", "method": "GET"}]
    detectors_mod.get("open-redirect").run(scanner)
    assert _findings(scanner, "open-redirect"), "外跳未被检出 → 漏报"


def test_open_redirect_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/redirect", "method": "GET"}]
    detectors_mod.get("open-redirect").run(scanner)
    assert not _findings(scanner, "open-redirect"), "安全的 redirect 被误报"


def test_host_header_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"host_header"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/profile", "method": "GET"}]
    detectors_mod.get("host-header").run(scanner)
    assert _findings(scanner, "host-header"), "Host 反射未被检出 → 漏报"


def test_host_header_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/profile", "method": "GET"}]
    detectors_mod.get("host-header").run(scanner)
    assert not _findings(scanner, "host-header"), "固定域名被误报为 Host 注入"
