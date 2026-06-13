"""
SSRF 检测器:带外(OOB)回连确认。经注册表打靶机,双向验证。
靶机 /fetch 在 ssrf 漏洞开时服务端抓取 url 参数 → 回连检测器的 OOB 监听器。
"""


def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def test_ssrf_detected_via_oob(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"ssrf"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/fetch", "method": "GET"}]
    detectors_mod.get("ssrf").run(scanner)
    found = _findings(scanner, "ssrf")
    assert found, "服务端回连受控地址却未检出 → 漏报"
    assert found[0]["severity"] == "high"


def test_ssrf_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()  # 安全:不抓取 url
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.public = [{"path": "/fetch", "method": "GET"}]
    detectors_mod.get("ssrf").run(scanner)
    assert not _findings(scanner, "ssrf"), "未发起回连却被误报为 SSRF"
