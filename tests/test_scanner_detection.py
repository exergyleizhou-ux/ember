"""
集成测试: scanner.Scanner 的真实检测方法,对着可开关漏洞的靶机端到端验证。

每个检测器都验证两面:
  - 漏洞开 → 必须产出对应 finding(否则漏报)
  - 漏洞关 → 必须不产出 finding(否则误报)

覆盖: AUTH-BYPASS / OPS-ESCALATE / IDOR。
"""


def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


# ── AUTH-BYPASS ──
def test_auth_bypass_detected(scanner_mod, make_vuln_server):
    server = make_vuln_server(vulns={"auth_bypass"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.scan_auth_bypass([{"path": "/jwt/thing", "method": "GET"}])
    found = _findings(scanner, "auth-bypass")
    assert found, "JWT 端点无 token 放行,未被检出 → 漏报"
    assert found[0]["severity"] == "high"


def test_auth_bypass_no_false_positive(scanner_mod, make_vuln_server):
    server = make_vuln_server()  # 安全
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.scan_auth_bypass([{"path": "/jwt/thing", "method": "GET"}])
    assert not _findings(scanner, "auth-bypass"), "安全的 JWT 端点被误报"


# ── OPS-ESCALATE ──
def test_ops_escalation_detected(scanner_mod, make_vuln_server):
    server = make_vuln_server(vulns={"ops_escalation"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.scan_ops_escalation([{"path": "/admin/thing", "method": "POST"}])
    found = _findings(scanner, "ops-escalate")
    assert found, "admin 端点对 buyer 放行,未被检出 → 漏报"
    assert found[0]["severity"] == "critical"


def test_ops_escalation_no_false_positive(scanner_mod, make_vuln_server):
    server = make_vuln_server()  # 安全:admin 端点对 buyer 返回 403
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.scan_ops_escalation([{"path": "/admin/thing", "method": "POST"}])
    assert not _findings(scanner, "ops-escalate"), "安全的 admin 端点被误报"


# ── IDOR ──
def test_idor_detected(scanner_mod, make_vuln_server):
    server = make_vuln_server(vulns={"idor"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.scan_idor()
    assert _findings(scanner, "idor"), "跨用户访问被放行,未被检出 → 漏报"


def test_idor_no_false_positive(scanner_mod, make_vuln_server):
    server = make_vuln_server()  # 安全:跨用户访问返回 404
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.scan_idor()
    assert not _findings(scanner, "idor"), "安全端点被误报为 IDOR"
