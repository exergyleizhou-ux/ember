"""
授权护栏(防误用)—— 攻击入口在开火前必须过这道门。

把守侧 scanner/scope.py 的授权逻辑接到攻击入口:
  - URL 目标(web/*):非本机目标必须 --scope 显式授权,否则拒绝并退出。
  - 实弹模式(ai/sender.py --live 朝真实模型开火):必须 --i-am-authorized 显式确认。
  - 两者都记录操作者(谁、对谁、何时),写 ~/.ember-operator.log + stderr。

纯约束 + 问责,不增强任何攻击能力。自包含(无跨包导入),任何攻击脚本可
`sys.path.insert(0, <repo_root>); from safety_gate import ...`。
"""

import getpass
import os
import sys
import time
from urllib.parse import urlparse

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _host(target: str) -> str:
    if not target:
        return ""
    parsed = urlparse(target if "://" in target else "//" + target)
    return (parsed.hostname or "").lower()


def _authorized(target: str, scope) -> bool:
    h = _host(target)
    if not h:
        return False
    if h in LOCAL_HOSTS:
        return True
    for a in scope:
        a = (a or "").strip().lower()
        if a and (h == a or h.endswith("." + a)):
            return True
    return False


def _log(tool: str, target: str):
    line = (f"{time.strftime('%Y-%m-%dT%H:%M:%S')} "
            f"operator={getpass.getuser()} tool={tool} target={target}")
    try:
        with open(os.path.join(os.path.expanduser("~"), ".ember-operator.log"), "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(f"📝 operator-log: {line}", file=sys.stderr)


def enforce_url_target(target: str, scope_csv: str, tool: str):
    """URL 目标授权门:非本机且不在 --scope 内 → 拒绝退出。通过则记日志。"""
    scope = [s for s in (scope_csv or "").split(",") if s.strip()]
    if not _authorized(target, scope):
        sys.exit(
            f"⛔ 授权护栏: 目标 {_host(target)!r} 不在授权范围。\n"
            f"   非本机目标必须用 --scope 显式声明授权,且你须持有书面授权。tool={tool}")
    _log(tool, target)


def enforce_live(authorized_flag: bool, tool: str, target: str = "(model)"):
    """实弹门:朝真实模型/目标开火必须 --i-am-authorized。通过则记日志。"""
    if not authorized_flag:
        sys.exit(
            f"⛔ 实弹护栏: 朝真实模型/目标开火需 --i-am-authorized "
            f"(你须确认对该目标拥有授权)。tool={tool}")
    _log(tool, target)
