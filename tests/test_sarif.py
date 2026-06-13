"""
单元测试: scanner.sarif — 报告→SARIF 2.1.0 转换。
SARIF 是对外集成契约,结构错了下游(GitHub Code Scanning 等)直接拒收,必须钉死。
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def sarif():
    spec = importlib.util.spec_from_file_location("ember_sarif", ROOT / "scanner" / "sarif.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def sample_report():
    return {
        "target": "http://localhost:8080",
        "scanned_at": "2026-06-13T00:00:00+00:00",
        "findings": [
            {"severity": "critical", "check": "ops-escalate", "path": "/admin/x",
             "method": "POST", "detail": "buyer token got 200", "evidence": ""},
            {"severity": "high", "check": "auth-bypass", "path": "/jwt/y",
             "method": "GET", "detail": "no token got 200", "evidence": ""},
            {"severity": "medium", "check": "info-leak", "path": "/search",
             "method": "GET", "detail": "token field leaked", "evidence": "{...}"},
            # 同一 check 重复,规则应去重
            {"severity": "high", "check": "auth-bypass", "path": "/jwt/z",
             "method": "GET", "detail": "another", "evidence": ""},
        ],
    }


def test_envelope(sarif, sample_report):
    doc = sarif.to_sarif(sample_report)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Ember"


@pytest.mark.parametrize("severity,level", [
    ("critical", "error"),
    ("high", "error"),
    ("medium", "warning"),
    ("low", "note"),
    ("weird", "note"),
])
def test_severity_to_level(sarif, severity, level):
    assert sarif.severity_to_level(severity) == level


def test_result_count_matches_findings(sarif, sample_report):
    doc = sarif.to_sarif(sample_report)
    results = doc["runs"][0]["results"]
    assert len(results) == 4  # 每个 finding 一条 result


def test_rules_deduplicated(sarif, sample_report):
    doc = sarif.to_sarif(sample_report)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # 4 个 finding 里 auth-bypass 出现两次 → 规则去重后 3 条
    assert sorted(rule_ids) == ["auth-bypass", "info-leak", "ops-escalate"]


def test_result_shape(sarif, sample_report):
    doc = sarif.to_sarif(sample_report)
    first = doc["runs"][0]["results"][0]
    assert first["ruleId"] == "ops-escalate"
    assert first["level"] == "error"
    assert first["message"]["text"]
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/admin/x"


def test_empty_report(sarif):
    doc = sarif.to_sarif({"target": "http://localhost", "findings": []})
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
