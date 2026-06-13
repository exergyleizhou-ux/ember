"""
mass-assignment 检测器:单元(纯反射判定)+ 集成(经注册表打靶机)。
双向:脆弱端点回显特权字段→检出;安全端点忽略→不误报。
"""

import pytest


@pytest.fixture(scope="module")
def ac(detectors_mod):
    # 经包加载,relative import 才有 parent package
    return detectors_mod.access_control


# ── 纯函数 ──
def test_reflected_privileged_fields_detects(ac):
    hit = ac.reflected_privileged_fields({"name": "x", "is_admin": True, "role": "admin"})
    assert set(hit) >= {"is_admin", "role"}


def test_reflected_unwraps_data_envelope(ac):
    hit = ac.reflected_privileged_fields({"data": {"role": "admin"}})
    assert "role" in hit


def test_reflected_ignores_non_injected_values(ac):
    # role 存在但不是注入值(admin)→ 不算命中
    assert ac.reflected_privileged_fields({"role": "user"}) == []


def test_reflected_empty_on_safe_response(ac):
    assert ac.reflected_privileged_fields({"name": "x"}) == []


# ── 集成 ──
def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def test_mass_assignment_detected(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server(vulns={"mass_assignment"})
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.jwt = [{"path": "/account/update", "method": "POST"}]
    detectors_mod.get("mass-assignment").run(scanner)
    found = _findings(scanner, "mass-assignment")
    assert found, "注入特权字段被接受却未检出 → 漏报"
    assert found[0]["severity"] == "high"


def test_mass_assignment_no_false_positive(scanner_mod, detectors_mod, make_vuln_server):
    server = make_vuln_server()  # 安全:忽略特权字段
    scanner = scanner_mod.Scanner(server.base_url)
    scanner.jwt = [{"path": "/account/update", "method": "POST"}]
    detectors_mod.get("mass-assignment").run(scanner)
    assert not _findings(scanner, "mass-assignment"), "安全端点被误报"
