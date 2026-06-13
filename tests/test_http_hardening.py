"""
集成测试: scanner._req 的限速与重试 —— 生产运行质量。
限速防止打挂目标;重试扛网络抖动。两者都用真实计时验证。
"""

import time


def test_rate_limit_spaces_requests(scanner_mod, vuln_server):
    """rate=5 → 间隔 ≥0.2s;连发 3 次应耗时 ≥0.4s(两个间隔)。"""
    scanner = scanner_mod.Scanner(vuln_server.base_url, rate=5.0)
    t0 = time.monotonic()
    for _ in range(3):
        scanner._req("GET", "/safe")
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.4, f"限速未生效,3 次仅耗时 {elapsed:.3f}s"


def test_no_throttle_by_default(scanner_mod, vuln_server):
    """默认 rate=0 不限速,3 次本机请求应很快。"""
    scanner = scanner_mod.Scanner(vuln_server.base_url)
    t0 = time.monotonic()
    for _ in range(3):
        scanner._req("GET", "/safe")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.4, f"默认不应限速,却耗时 {elapsed:.3f}s"


def test_retry_on_connection_failure(scanner_mod):
    """打一个关闭的端口 → 连接失败重试 2 次(退避 0.2+0.4=0.6s)后返回 0。"""
    scanner = scanner_mod.Scanner("http://127.0.0.1:1", retries=2)
    t0 = time.monotonic()
    status, body, _ = scanner._req("GET", "/whatever")
    elapsed = time.monotonic() - t0
    assert status == 0, "连接失败应返回状态 0"
    assert elapsed >= 0.5, f"应有退避重试,却仅耗时 {elapsed:.3f}s(没重试?)"


def test_no_retry_means_faster_failure(scanner_mod):
    """retries=0 → 不重试,立即失败,明显快于带重试。"""
    scanner = scanner_mod.Scanner("http://127.0.0.1:1", retries=0)
    t0 = time.monotonic()
    status, _, _ = scanner._req("GET", "/whatever")
    elapsed = time.monotonic() - t0
    assert status == 0
    assert elapsed < 0.5, f"retries=0 不应退避,却耗时 {elapsed:.3f}s"
