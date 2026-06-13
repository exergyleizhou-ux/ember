"""
单元测试: engine.WebAttacker._analyze — 这是注入引擎的"判定大脑"。
它决定一次响应算不算命中。误判会直接变成误报/漏报,必须钉死。

_analyze(category, safe_body, injected_body, safe_time, injected_time) -> dict
判定优先级: 时间盲注 > 报错泄露 > 长度异常 > probably_not
"""

import pytest


@pytest.fixture()
def attacker(engine_mod):
    # target 不会被真正请求,_analyze 是纯函数式判定
    return engine_mod.WebAttacker("http://127.0.0.1:1")


def test_time_based_blind_detected(attacker):
    verdict = attacker._analyze("sqli", "ok", "ok", safe_time=0.1, injected_time=2.0)
    assert verdict["verdict"] == "time_based_hit"
    assert verdict["confidence"] == "high"


def test_sql_error_disclosure_detected(attacker):
    safe = '{"results": []}'
    injected = '{"error": "You have an error in your SQL syntax near ..."}'
    verdict = attacker._analyze("sqli", safe, injected, 0.1, 0.1)
    assert verdict["verdict"] == "error_disclosure"


def test_error_already_in_baseline_not_flagged(attacker):
    # 若安全响应里本就有该模式,注入响应再出现就不算新增泄露 → 不命中
    noisy = "PostgreSQL banner always present"
    verdict = attacker._analyze("sqli", noisy, noisy + " more", 0.1, 0.1)
    assert verdict["verdict"] != "error_disclosure"


def test_large_response_anomaly_detected(attacker):
    safe = "x" * 10
    injected = "x" * 800  # 差异 > 500 字节
    verdict = attacker._analyze("sqli", safe, injected, 0.1, 0.1)
    assert verdict["verdict"] == "response_anomaly"


def test_identical_response_not_flagged(attacker):
    body = '{"results": []}'
    verdict = attacker._analyze("sqli", body, body, 0.1, 0.12)
    assert verdict["verdict"] == "probably_not"


def test_small_difference_not_flagged(attacker):
    # 正常的轻微差异不应触发长度异常
    verdict = attacker._analyze("sqli", "a" * 100, "a" * 120, 0.1, 0.1)
    assert verdict["verdict"] == "probably_not"
