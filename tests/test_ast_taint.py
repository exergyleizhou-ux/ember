"""ast_taint 静态污点分析器单元测试。"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def at():
    spec = importlib.util.spec_from_file_location(
        "ember_ast_taint", ROOT / "scanner" / "llm_app" / "ast_taint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rules(at, code):
    return sorted({f["rule"] for f in at.analyze(code)})


# ── 三类 sink 检出 ──
def test_indirect_injection_detected(at):
    code = ("def h():\n"
            "    data = requests.get(url).text\n"
            "    client.chat.completions.create(messages=[{'content': data}])\n")
    assert "llm-indirect-injection-sink" in rules(at, code)


def test_indirect_injection_via_fstring(at):
    code = ("def h():\n"
            "    data = fetch_url(u)\n"
            "    prompt = f'summarize: {data}'\n"
            "    llm.invoke(prompt)\n")
    assert "llm-indirect-injection-sink" in rules(at, code)


@pytest.mark.parametrize("sink", ["os.system(data)", "eval(data)",
                                  "subprocess.run(data)", "exec(data)"])
def test_confused_deputy_detected(at, sink):
    code = f"def h():\n    data = fetch_url(u)\n    {sink}\n"
    assert "llm-tool-confused-deputy" in rules(at, code)


def test_output_exfil_detected(at):
    code = ("def h():\n"
            "    out = client.chat.completions.create(messages=m)\n"
            "    st.markdown(out)\n")
    assert "llm-output-exfil" in rules(at, code)


@pytest.mark.parametrize("sink", ["exec(out)", "eval(out)", "subprocess.run(out)"])
def test_code_exec_detected(at, sink):
    # LLM 输出 → 代码执行 = llm-code-exec(RCE 面)
    code = f"def h():\n    out = llm.invoke(p)\n    {sink}\n"
    assert "llm-code-exec" in rules(at, code)


def test_code_exec_distinct_from_confused_deputy(at):
    # ext→eval 是 confused-deputy;llm→eval 是 code-exec,两者不同源不同色
    ext = "def h():\n    d = fetch_url(u)\n    eval(d)\n"
    llm = "def h():\n    o = llm.invoke(p)\n    eval(o)\n"
    assert "llm-tool-confused-deputy" in rules(at, ext)
    assert "llm-code-exec" not in rules(at, ext)
    assert "llm-code-exec" in rules(at, llm)
    assert "llm-tool-confused-deputy" not in rules(at, llm)


def test_code_exec_sanitized_not_flagged(at):
    code = ("def h():\n"
            "    o = llm.invoke(p)\n"
            "    safe = whitelist_match(o, ALLOWED)\n"
            "    exec(safe)\n")
    assert "llm-code-exec" not in rules(at, code)


# ── 无误报 ──
def test_sanitized_not_flagged(at):
    code = ("def h():\n"
            "    data = requests.get(url).text\n"
            "    clean = schema_extract(data, Schema)\n"
            "    client.chat.completions.create(messages=[{'content': clean}])\n")
    assert rules(at, code) == []


def test_assert_trusted_is_sanitizer(at):
    code = ("def h():\n"
            "    data = fetch_url(u)\n"
            "    safe = assert_trusted(data, 'sink')\n"
            "    os.system(safe)\n")
    # assert_trusted 在静态层视为去污点(它在运行时会抛,等价于"这里已守住")
    assert "llm-tool-confused-deputy" not in rules(at, code)


def test_benign_no_external_source(at):
    code = ("def h():\n"
            "    msg = 'hello'\n"
            "    client.chat.completions.create(messages=[{'content': msg}])\n")
    assert rules(at, code) == []


def test_per_function_scope_no_leak(at):
    # a() 里的 tainted 不应泄漏到 b()
    code = ("def a():\n"
            "    data = requests.get(u).text\n"
            "def b():\n"
            "    os.system(data)\n")
    assert rules(at, code) == []


def test_syntax_error_returns_empty(at):
    assert at.analyze("def (((") == []


def test_finding_carries_line_and_sink(at):
    code = ("def h():\n"
            "    data = requests.get(u).text\n"
            "    os.system(data)\n")
    flows = [f for f in at.analyze(code, "x.py") if f["rule"] == "llm-tool-confused-deputy"]
    assert flows and flows[0]["line"] == 3 and "system" in flows[0]["sink"]
