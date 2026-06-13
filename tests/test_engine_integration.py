"""
集成测试: 把注入引擎指向真实跑起来的靶机,端到端验证两件事 ——
  1. 对已知脆弱端点必须命中(否则是漏报)
  2. 对健康端点必须不命中(否则是误报)

这是"扫描器可信"的最低门槛。
"""



def test_detects_known_sqli_endpoint(engine_mod, vuln_server):
    """/search 会反射 SQL 报错 → 必须被检出。"""
    attacker = engine_mod.WebAttacker(vuln_server.base_url)
    results = attacker.probe_category("sqli", ["/search"])

    assert results, "应当产生探测结果"
    hits = [r for r in results if r["hit"]]
    assert hits, "已知脆弱的 /search 未被检出 → 漏报"
    # 报错型应被判为 error_disclosure
    assert any(h["analysis"]["verdict"] == "error_disclosure" for h in hits)


def test_no_false_positive_on_healthy_endpoint(engine_mod, vuln_server):
    """/safe 恒定响应、忽略输入 → 不应命中。"""
    attacker = engine_mod.WebAttacker(vuln_server.base_url)
    results = attacker.probe_category("sqli", ["/safe"])

    assert results, "应当产生探测结果"
    hits = [r for r in results if r["hit"]]
    assert not hits, f"健康端点 /safe 被误报: {[h['payload'] for h in hits]}"


def test_time_based_blind_detected_end_to_end(engine_mod, vuln_server):
    """含 sleep 的 payload 会让靶机延迟 2s → 时间盲注检出。"""
    attacker = engine_mod.WebAttacker(vuln_server.base_url)
    # 直接复用引擎的判定路径:发一个 sleep payload
    status, body, elapsed = attacker._req("GET", "/search", params={"q": "1' AND SLEEP(5)--"})
    verdict = attacker._analyze("sqli", "", body, safe_time=0.05, injected_time=elapsed)
    assert verdict["verdict"] == "time_based_hit", f"耗时 {elapsed:.2f}s 未触发时间盲注判定"
