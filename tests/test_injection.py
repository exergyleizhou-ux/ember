"""
注入检测器家族:单元(纯分析)+ 集成(经注册表打靶机,双向钉死)。
覆盖 SQLi(报错/时间盲注)· 反射 XSS · 命令注入 · SSTI · 路径遍历。
"""

import pytest


@pytest.fixture(scope="module")
def inj(detectors_mod):
    return detectors_mod.injection


def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


# ── 纯分析函数 ──
def test_new_sql_error(inj):
    assert inj.new_sql_error("{}", '{"error":"You have an error in your SQL syntax"}') is True
    # 基线本就有该模式 → 不算新增
    assert inj.new_sql_error("SQL syntax noise", "SQL syntax noise too") is False


def test_reflected_unencoded(inj):
    assert inj.reflected_unencoded(inj.XSS_MARKER, f'{{"echo":"{inj.XSS_MARKER}"}}') is True
    assert inj.reflected_unencoded(inj.XSS_MARKER, '{"echo":"&lt;ember-xss-9d3f&gt;"}') is False


def test_ssti_evaluated(inj):
    assert inj.ssti_evaluated('{"rendered":"1787569"}') is True
    assert inj.ssti_evaluated('{"rendered":"{{1337*1337}}"}') is False


def test_passwd_leaked(inj):
    assert inj.passwd_leaked("root:x:0:0:root:/root:/bin/bash") is True
    assert inj.passwd_leaked("not found") is False


# ── 集成:SQLi(/search 报错型)──
def test_sqli_detected(scanner_mod, detectors_mod, vuln_server):
    s = scanner_mod.Scanner(vuln_server.base_url)
    s.public = [{"path": "/search", "method": "GET"}]
    detectors_mod.get("sqli-active").run(s)
    assert _findings(s, "sqli-active"), "报错型 SQLi 未检出"


def test_sqli_no_false_positive(scanner_mod, detectors_mod, vuln_server):
    s = scanner_mod.Scanner(vuln_server.base_url)
    s.public = [{"path": "/safe", "method": "GET"}]
    detectors_mod.get("sqli-active").run(s)
    assert not _findings(s, "sqli-active"), "安全端点被误报为 SQLi"


# ── XSS ──
def test_xss_detected(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server(vulns={"xss"}).base_url)
    s.public = [{"path": "/xss", "method": "GET"}]
    detectors_mod.get("xss-reflected").run(s)
    assert _findings(s, "xss-reflected"), "反射 XSS 未检出"


def test_xss_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server().base_url)  # 安全:HTML 编码
    s.public = [{"path": "/xss", "method": "GET"}]
    detectors_mod.get("xss-reflected").run(s)
    assert not _findings(s, "xss-reflected"), "编码输出被误报为 XSS"


# ── SSTI ──
def test_ssti_detected(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server(vulns={"ssti"}).base_url)
    s.public = [{"path": "/ssti", "method": "GET"}]
    detectors_mod.get("ssti").run(s)
    assert _findings(s, "ssti"), "SSTI 未检出"


def test_ssti_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server().base_url)  # 安全:原样回显不求值
    s.public = [{"path": "/ssti", "method": "GET"}]
    detectors_mod.get("ssti").run(s)
    assert not _findings(s, "ssti"), "回显未求值被误报为 SSTI"


# ── 命令注入(时间盲注)──
def test_cmdi_detected(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server(vulns={"cmdi"}).base_url)
    s.public = [{"path": "/cmd", "method": "GET"}]
    detectors_mod.get("command-injection").run(s)
    assert _findings(s, "command-injection"), "命令注入未检出"


def test_cmdi_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server().base_url)
    s.public = [{"path": "/cmd", "method": "GET"}]
    detectors_mod.get("command-injection").run(s)
    assert not _findings(s, "command-injection"), "无延迟却被误报为命令注入"


# ── 路径遍历 ──
def test_path_traversal_detected(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server(vulns={"path_traversal"}).base_url)
    s.public = [{"path": "/readfile", "method": "GET"}]
    detectors_mod.get("path-traversal").run(s)
    assert _findings(s, "path-traversal"), "路径遍历未检出"


def test_path_traversal_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    s = scanner_mod.Scanner(make_vuln_server().base_url)
    s.public = [{"path": "/readfile", "method": "GET"}]
    detectors_mod.get("path-traversal").run(s)
    assert not _findings(s, "path-traversal"), "安全端点被误报为路径遍历"
