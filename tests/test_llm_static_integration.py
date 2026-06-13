"""
LLM 静态检测器(经注册表)集成测试:对源码文件双向验证。
"""

import pytest

VULN = (
    "def handle(url):\n"
    "    data = requests.get(url).text\n"
    "    reply = client.chat.completions.create(messages=[{'content': data}])\n"
    "    st.markdown(reply)\n"
    "    os.system(data)\n"
)

SAFE = (
    "def handle(url):\n"
    "    data = requests.get(url).text\n"
    "    clean = schema_extract(data, Schema)\n"
    "    reply = client.chat.completions.create(messages=[{'content': clean}])\n"
    "    archive()\n"
)


def _findings(scanner, check):
    return [f for f in scanner.findings if f["check"] == check]


def _scan(scanner_mod, detectors_mod, code, det_name):
    scanner = scanner_mod.Scanner("")
    scanner.source_files = [("agent.py", code)]
    detectors_mod.get(det_name).run(scanner)
    return scanner


@pytest.mark.parametrize("det_name", [
    "llm-indirect-injection-sink",
    "llm-tool-confused-deputy",
    "llm-output-exfil",
])
def test_static_detectors_flag_vulnerable(scanner_mod, detectors_mod, det_name):
    scanner = _scan(scanner_mod, detectors_mod, VULN, det_name)
    assert _findings(scanner, det_name), f"{det_name}: 脆弱源码未检出"


@pytest.mark.parametrize("det_name", [
    "llm-indirect-injection-sink",
    "llm-tool-confused-deputy",
    "llm-output-exfil",
])
def test_static_detectors_no_false_positive(scanner_mod, detectors_mod, det_name):
    scanner = _scan(scanner_mod, detectors_mod, SAFE, det_name)
    assert not _findings(scanner, det_name), f"{det_name}: 安全源码被误报"


def test_static_detector_mode_is_static(detectors_mod):
    assert detectors_mod.get("llm-indirect-injection-sink").mode == "static"
