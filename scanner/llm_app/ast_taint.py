"""
LLM 应用静态污点分析(守侧 SAST)。

在单文件 / 单函数作用域内(intraprocedural MVP)追两种污点:
  - ext  : 外部不可信数据(网页/邮件/上传/HTTP 入参)
  - llm  : LLM 输出(可能被间接注入污染,含 markdown 外泄)

规则:
  - 变量从 SOURCE 调用赋值 → ext 污点
  - 变量从 LLM 调用赋值       → llm 污点
  - 经 SANITIZER 调用         → 去污点
  - ext 污点流进 LLM 调用参数 → 间接注入 sink
  - ext 污点流进危险/工具参数 → confused deputy(eval/exec/os.system/subprocess/SQL/HTTP)
  - llm 污点流进渲染 sink     → 输出外泄(markdown/HTML)

诚实局限:intraprocedural、基于调用名签名;跨函数/跨文件不追,会漏报。
故意保守去污点(只认显式 sanitizer),宁可漏报不误报。完整版可上 pysa。
"""

import ast
from typing import List, Optional, Set

# ── 调用名签名(按 dotted name 后缀 / 子串匹配)──
SOURCE_MARKERS = (
    "requests.get", "requests.post", "requests.request",
    "httpx.get", "httpx.post", "urlopen",
    "fetch_url", "read_email_body", "read_uploaded_file",
    "request.args", "request.form", "request.json", "request.get_json", "request.data",
)
LLM_SINK_MARKERS = (
    "completions.create", "messages.create", "chat.completions.create",
    "litellm.completion", ".completion", ".invoke", ".chat", ".complete",
    ".generate", "ChatCompletion.create", "generate_content",
)
TOOL_SINK_MARKERS = (
    "eval", "exec", "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
    "execute", "executemany", "send_email", "http_request",
)
RENDER_SINK_MARKERS = (
    "st.markdown", "st.write", "st.html", "markdown", "render_template",
    "render_template_string", "display", "HTML", "to_html", "Markdown",
)
SANITIZER_MARKERS = (
    "schema_extract", "whitelist_match", "human_confirm", "assert_trusted",
    "model_validate", "parse_obj", "parse_raw", "model_validate_json",
)


def _call_name(node: ast.AST) -> str:
    """取一个 Call.func 的点路径,如 client.chat.completions.create。"""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _matches(name: str, markers) -> bool:
    return any(m in name or name.endswith(m.lstrip(".")) for m in markers)


class _Flow:
    def __init__(self, category, rule, line, source_kind, sink, snippet):
        self.category = category    # "llm" | "tool" | "output"
        self.rule = rule
        self.line = line
        self.source_kind = source_kind
        self.sink = sink
        self.snippet = snippet

    def as_dict(self):
        return {"category": self.category, "rule": self.rule, "line": self.line,
                "source_kind": self.source_kind, "sink": self.sink, "snippet": self.snippet}


class _ScopeAnalyzer:
    def __init__(self):
        self.ext: Set[str] = set()
        self.llm: Set[str] = set()
        self.flows: List[_Flow] = []

    # 表达式携带的污点颜色集合
    def expr_taint(self, node: Optional[ast.AST]) -> Set[str]:
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            colors = set()
            if node.id in self.ext:
                colors.add("ext")
            if node.id in self.llm:
                colors.add("llm")
            return colors
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if _matches(name, SANITIZER_MARKERS):
                return set()                      # 去污点
            if _matches(name, SOURCE_MARKERS):
                return {"ext"}
            if _matches(name, LLM_SINK_MARKERS):
                return {"llm"}                    # LLM 输出
            # 未知调用:参数污点向上传播(保守保召回)
            colors = set()
            for a in list(node.args) + [kw.value for kw in node.keywords]:
                colors |= self.expr_taint(a)
            return colors
        if isinstance(node, ast.BinOp):
            return self.expr_taint(node.left) | self.expr_taint(node.right)
        if isinstance(node, ast.JoinedStr):
            colors = set()
            for v in node.values:
                colors |= self.expr_taint(v)
            return colors
        if isinstance(node, ast.FormattedValue):
            return self.expr_taint(node.value)
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            return self.expr_taint(node.value)
        if isinstance(node, (ast.BoolOp,)):
            colors = set()
            for v in node.values:
                colors |= self.expr_taint(v)
            return colors
        if isinstance(node, ast.IfExp):
            return self.expr_taint(node.body) | self.expr_taint(node.orelse)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            colors = set()
            for e in node.elts:
                colors |= self.expr_taint(e)
            return colors
        if isinstance(node, ast.Dict):
            colors = set()
            for k, v in zip(node.keys, node.values):
                colors |= self.expr_taint(k) | self.expr_taint(v)
            return colors
        return set()

    def _check_sinks_in(self, node: ast.AST):
        """在一条语句的所有 Call 里找 sink + 污点参数。"""
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = _call_name(call.func)
            arg_nodes = list(call.args) + [kw.value for kw in call.keywords]
            arg_colors = set()
            for a in arg_nodes:
                arg_colors |= self.expr_taint(a)

            if _matches(name, LLM_SINK_MARKERS) and "ext" in arg_colors:
                self.flows.append(_Flow(
                    "llm", "llm-indirect-injection-sink", call.lineno,
                    "external-data", name,
                    "外部不可信数据未经净化就进了 LLM 调用(间接注入面)"))
            if _matches(name, TOOL_SINK_MARKERS) and "ext" in arg_colors:
                self.flows.append(_Flow(
                    "tool", "llm-tool-confused-deputy", call.lineno,
                    "external-data", name,
                    f"外部数据流到危险/工具调用 {name}(confused deputy)"))
            if _matches(name, RENDER_SINK_MARKERS) and "llm" in arg_colors:
                self.flows.append(_Flow(
                    "output", "llm-output-exfil", call.lineno,
                    "llm-output", name,
                    f"LLM 输出未净化就渲染到 {name}(markdown/HTML 外泄面)"))

    def _apply_assign(self, targets, value):
        colors = self.expr_taint(value)
        names = []
        for t in targets:
            if isinstance(t, ast.Name):
                names.append(t.id)
            elif isinstance(t, (ast.Tuple, ast.List)):
                names += [e.id for e in t.elts if isinstance(e, ast.Name)]
        for n in names:
            # 先清后置:重新赋值会覆盖旧污点
            self.ext.discard(n)
            self.llm.discard(n)
            if "ext" in colors:
                self.ext.add(n)
            if "llm" in colors:
                self.llm.add(n)

    def run(self, body):
        for stmt in body:
            # 嵌套函数有独立作用域,这里不下钻(由 analyze 单独跑)
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # 1) 先用当前污点判 sink
            self._check_sinks_in(stmt)
            # 2) 再应用赋值效果
            if isinstance(stmt, ast.Assign):
                self._apply_assign(stmt.targets, stmt.value)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                self._apply_assign([stmt.target], stmt.value)
            # 3) 复合语句:在同一作用域内递归子块
            for attr in ("body", "orelse", "finalbody"):
                block = getattr(stmt, attr, None)
                if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                    self.run(block)
            for handler in getattr(stmt, "handlers", []) or []:
                self.run(handler.body)


def _iter_scopes(tree):
    """模块顶层 body 作为一个作用域;每个(异步)函数体各作为独立作用域。"""
    yield [s for s in tree.body
           if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.body


def analyze(code: str, filename: str = "<src>") -> List[dict]:
    """分析源码,返回 flow 字典列表(去重)。语法错误返回空。"""
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        return []
    flows = []
    for scope_body in _iter_scopes(tree):
        analyzer = _ScopeAnalyzer()
        analyzer.run(scope_body)
        flows.extend(analyzer.flows)
    seen = set()
    out = []
    for f in flows:
        key = (f.rule, f.line, f.sink)
        if key in seen:
            continue
        seen.add(key)
        out.append({**f.as_dict(), "file": filename})
    return out
