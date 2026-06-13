"""
冒烟测试: 统一启动器 run.py 端到端。
启动器把各层用子进程串起来 —— 这部分最容易在重构后悄悄断掉。
这里真跑一遍: run.py → 子进程 scanner → 打靶机 → 出 HTML 报告。
"""

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
        security:
          - bearerAuth: []
        paths:
          /jwt/thing:
            get: {responses: {'200': {description: ok}}}
          /admin/thing:
            post: {responses: {'200': {description: ok}}}
          /auth/login:
            post:
              security: []
              responses: {'200': {description: ok}}
        """
    )
    path = tmp_path / "openapi.yaml"
    path.write_text(spec)
    return str(path)


def test_run_launcher_end_to_end(vuln_server, minimal_spec, tmp_path):
    out_dir = tmp_path / "reports"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "run.py"),
         "-t", vuln_server.base_url,
         "--spec", minimal_spec,
         "--quick",
         "--output", str(out_dir)],
        capture_output=True, text=True, timeout=120, cwd=str(ROOT),
    )

    assert proc.returncode == 0, f"启动器非零退出\nSTDOUT:{proc.stdout[-800:]}\nSTDERR:{proc.stderr[-800:]}"
    reports = list(out_dir.glob("scan-*.html"))
    assert reports, "未生成 HTML 报告"
    assert reports[0].stat().st_size > 0, "HTML 报告为空"


def test_run_launcher_refuses_unauthorized_remote(tmp_path):
    """非本机目标且无 --scope → 启动器应拒绝并非零退出。"""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "run.py"),
         "-t", "https://prod.example.com/api",
         "--output", str(tmp_path / "reports")],
        capture_output=True, text=True, timeout=30, cwd=str(ROOT),
    )
    assert proc.returncode != 0, "未授权远程目标本应被拒绝"
    assert "授权" in (proc.stdout + proc.stderr)
