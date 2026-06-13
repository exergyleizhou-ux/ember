"""
safety_gate 单元测试 —— 攻击入口的授权护栏(防误用 + 问责)。
纯约束逻辑;不涉及任何攻击行为。
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def sg():
    spec = importlib.util.spec_from_file_location("ember_safety_gate", ROOT / "safety_gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 授权判定 ──
@pytest.mark.parametrize("target", ["http://localhost:8080", "http://127.0.0.1/x", "https://0.0.0.0"])
def test_localhost_authorized(sg, target):
    assert sg._authorized(target, []) is True


def test_remote_denied_without_scope(sg):
    assert sg._authorized("https://prod.example.com", []) is False


def test_remote_allowed_in_scope(sg):
    assert sg._authorized("https://api.example.com", ["example.com"]) is True


# ── enforce_url_target ──
def test_enforce_url_refuses_unauthorized(sg):
    with pytest.raises(SystemExit):
        sg.enforce_url_target("https://prod.example.com", "", "web/chain.py")


def test_enforce_url_passes_localhost(sg):
    sg.enforce_url_target("http://localhost:3000", "", "web/chain.py")  # 不应抛


def test_enforce_url_passes_scoped(sg):
    sg.enforce_url_target("https://prod.example.com", "example.com", "web/chain.py")


# ── enforce_live ──
def test_enforce_live_refuses_without_flag(sg):
    with pytest.raises(SystemExit):
        sg.enforce_live(False, "ai/sender.py", "claude")


def test_enforce_live_passes_with_flag(sg):
    sg.enforce_live(True, "ai/sender.py", "claude")


# ── 端到端冒烟:攻击入口在攻击前先被护栏拦下(只测拒绝路径,不触发攻击)──
# 攻击脚本有重依赖(aiohttp 等),无依赖环境(CI)会在 import 阶段就退出;
# 那种情况脚本根本跑不起来=也安全,这里 skip(护栏逻辑由上面的单测担保)。
def _gate_check(argv):
    proc = subprocess.run([sys.executable] + argv, capture_output=True, text=True,
                          timeout=30, cwd=str(ROOT))
    out = proc.stdout + proc.stderr
    if any(m in out for m in ("ModuleNotFoundError", "ImportError", "No module named")):
        pytest.skip("攻击脚本依赖未安装(本环境)— 护栏逻辑已由单测覆盖")
    return proc.returncode != 0 and "护栏" in out


def test_chain_gate_blocks_unauthorized_remote():
    assert _gate_check(["web/chain.py", "-t", "https://prod.example.com", "--chain", "recon"])


def test_sender_live_gate_blocks_without_authorization():
    # --live 但无 --i-am-authorized → 实弹门拦下,不发送
    assert _gate_check(["ai/sender.py", "-m", "claude", "--auto", "1", "--live"])
