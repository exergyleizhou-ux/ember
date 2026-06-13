"""
pytest 共享夹具。

仓库没有包结构,模块以脚本形式散落在子目录里。这里用 importlib 按文件路径
加载被测模块,避免改动现有代码,也避免 sys.path 污染。
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(module_name: str, relative_path: str):
    """按文件路径加载一个模块并注册到 sys.modules。"""
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def scanner_mod():
    """scanner/scanner.py — API 扫描引擎。"""
    # 扫描器内部有同级导入(web_checks 等),按 CLI 运行方式把包目录放上 path
    sys.path.insert(0, str(ROOT / "scanner"))
    return _load("ember_scanner", "scanner/scanner.py")


@pytest.fixture(scope="session")
def engine_mod():
    """payloads/engine.py — payload 注入引擎。"""
    return _load("ember_engine", "payloads/engine.py")


@pytest.fixture(scope="session")
def detectors_mod(scanner_mod):
    """scanner/detectors 注册表包(scanner_mod 已把包目录放上 path)。"""
    import importlib
    return importlib.import_module("detectors")


@pytest.fixture()
def vuln_server():
    """启动一个完全安全的靶机,测试结束后关闭。"""
    sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
    from vulnerable_target import VulnerableServer

    server = VulnerableServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture()
def make_vuln_server():
    """工厂:make_vuln_server(vulns={...}) 起一台指定漏洞开关的靶机,
    所有起出来的实例在测试结束统一关闭。"""
    sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
    from vulnerable_target import VulnerableServer

    started = []

    def _factory(vulns=frozenset()):
        server = VulnerableServer(vulns=vulns).start()
        started.append(server)
        return server

    try:
        yield _factory
    finally:
        for server in started:
            server.stop()
