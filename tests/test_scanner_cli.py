"""
回归测试: 直接把 scanner.py 当 CLI 跑到底,验证 main() 完整收尾。

为什么需要它:此前 main() 在汇总行有个 KeyError(把顶层 duration_seconds
误当成 stats 字段),导致 CLI 每次都在最后崩、--sarif 永远不写出。
单元/集成测试直呼 scan 方法、绕过了 main(),所以一直没抓到。这条测试堵住这个口子。
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def minimal_spec(tmp_path):
    spec = textwrap.dedent(
        """
        openapi: 3.0.0
        info: {title: t, version: '1'}
        paths:
          /search:
            get:
              security: []
              responses: {'200': {description: ok}}
        """
    )
    path = tmp_path / "openapi.yaml"
    path.write_text(spec)
    return str(path)


def test_scanner_cli_runs_to_completion_and_writes_sarif(vuln_server, minimal_spec, tmp_path):
    sarif_path = tmp_path / "out.sarif"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scanner" / "scanner.py"),
         "-t", vuln_server.base_url,
         "--spec", minimal_spec,
         "--quick",
         "--sarif", str(sarif_path)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"扫描器 CLI 非零退出\nSTDERR:\n{proc.stderr[-1000:]}"
    assert sarif_path.exists(), "--sarif 指定了却没写出 SARIF"

    doc = json.loads(sarif_path.read_text())
    assert doc["version"] == "2.1.0"
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    # 默认 probe "/" 无安全头 → 必含 sec-headers 规则,证明新检查接进了主流程
    assert "sec-headers" in rule_ids
