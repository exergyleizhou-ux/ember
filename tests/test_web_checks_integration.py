"""
集成测试: scanner 的安全头 / CORS 扫描方法,对着靶机端到端。
双向验证:脆弱对照点→检出,安全对照点→不误报。
"""


def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


# ── 安全响应头 ──
def test_security_headers_missing_detected(scanner_mod, vuln_server):
    scanner = scanner_mod.Scanner(vuln_server.base_url)
    scanner.scan_security_headers("/headers/insecure")
    found = _findings(scanner, "sec-headers")
    # 4 个安全头全缺 → 4 条 finding
    assert len(found) == 4, f"应检出 4 个缺失安全头,实际 {len(found)}"


def test_security_headers_present_no_finding(scanner_mod, vuln_server):
    scanner = scanner_mod.Scanner(vuln_server.base_url)
    scanner.scan_security_headers("/headers/secure")
    assert not _findings(scanner, "sec-headers"), "齐全的安全头被误报"


# ── CORS ──
def test_cors_reflect_detected(scanner_mod, vuln_server):
    scanner = scanner_mod.Scanner(vuln_server.base_url)
    scanner.scan_cors("/cors/reflect")
    found = _findings(scanner, "cors")
    assert found, "回显任意 Origin 的 CORS 未被检出"
    assert found[0]["severity"] == "high"  # 回显 + 允许凭证


def test_cors_safe_no_finding(scanner_mod, vuln_server):
    scanner = scanner_mod.Scanner(vuln_server.base_url)
    scanner.scan_cors("/cors/safe")
    assert not _findings(scanner, "cors"), "固定可信域的 CORS 被误报"
