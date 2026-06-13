"""
集成测试: JWT 检测器(经注册表)对着靶机端到端。
靶机 /jwt-login 发真 HS256 JWT,/jwt/protected 校验;漏洞开关放行对应伪造。
双向:漏洞开→检出、漏洞关→不误报。无 token→跳过。
"""

import json
import urllib.request


def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def _login(base_url):
    with urllib.request.urlopen(f"{base_url}/jwt-login", timeout=5) as r:
        return json.loads(r.read())["token"]


def _setup(scanner_mod, server):
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.token = _login(server.base_url)
    scanner.jwt = [{"path": "/jwt/protected", "method": "GET"}]
    return scanner


CASES = [
    ("jwt-alg-none", "jwt_alg_none"),
    ("jwt-unsigned", "jwt_unsigned"),
    ("jwt-sig-not-verified", "jwt_no_verify"),
]


def test_jwt_forgeries_detected(scanner_mod, detectors_mod, make_vuln_server):
    for det_name, vuln in CASES:
        server = make_vuln_server(vulns={vuln})
        scanner = _setup(scanner_mod, server)
        detectors_mod.get(det_name).run(scanner)
        found = _findings(scanner, det_name)
        assert found, f"{det_name}: 伪造被接受却未检出 → 漏报"
        assert found[0]["severity"] == "critical"


def test_jwt_no_false_positive_on_secure(scanner_mod, detectors_mod, make_vuln_server):
    for det_name, _ in CASES:
        server = make_vuln_server()  # 安全:拒绝一切伪造
        scanner = _setup(scanner_mod, server)
        detectors_mod.get(det_name).run(scanner)
        assert not _findings(scanner, det_name), f"{det_name}: 安全服务端被误报"


def test_jwt_skipped_without_token(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"jwt_alg_none"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.jwt = [{"path": "/jwt/protected", "method": "GET"}]
    # 不设置 token → 应跳过,不产出 finding
    detectors_mod.get("jwt-alg-none").run(scanner)
    assert not _findings(scanner, "jwt-alg-none")
