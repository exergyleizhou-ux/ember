# Taint-Tracking 框架(Python)

> **目的**:运行时强制 dual-LLM 架构的不变量 I2(tainted 数据不直接进 P-LLM)和 I4(工具关键参数必须是常量,不来自 tainted 源)。
>
> **思想来源**:Perl `-T` taint mode、Ruby `$SAFE`、Django/Rails 的 SafeString;现代 LLM 应用版本:Microsoft TaskTracker (2024)、UC Berkeley FIDES (arXiv:2404.13733)。
>
> **目标读者**:写 LLM agent 的 Python 工程师。

---

## 1. 核心概念

**Taint(污点)** = 字符串/对象的元数据,标记"这块数据来自不可信源"。
**Source** = taint 进入系统的入口(HTTP 抓取、文件读取、邮件正文、用户上传)。
**Sink** = taint 不能流到的目的地(P-LLM prompt、工具的 constant_only 参数、shell 命令)。
**Sanitizer** = 显式去除 taint 的操作(schema 抽取、白名单匹配、人工确认)。

```
  source  ─→ tainted data ─→ ... ─→ sanitizer ─→ trusted data ─→ sink ✓
                                ─→ ─→ ─→ ─→ ─→ ─→ ─→ ─→ ─→ tainted ─→ sink ✗ (RAISE)
```

---

## 2. Python 实现

### 2.1 Tainted 字符串类型

```python
# scanner/llm_app/taint.py
from __future__ import annotations
from typing import Optional

class Tainted(str):
    """A str subclass that carries a taint tag.

    Most str operations propagate taint. Casting to plain str requires
    going through a sanitizer.
    """
    __slots__ = ("_source", "_chain")

    def __new__(cls, value: str, source: str, chain: Optional[tuple] = None):
        obj = super().__new__(cls, value)
        obj._source = source
        obj._chain = chain or (source,)
        return obj

    @property
    def source(self) -> str:
        return self._source

    @property
    def provenance(self) -> tuple:
        return self._chain

    # taint-propagating ops
    def __add__(self, other):
        result = str.__add__(self, str(other))
        other_chain = getattr(other, "_chain", ())
        return Tainted(result, self._source, self._chain + other_chain)

    def __radd__(self, other):
        result = str.__add__(str(other), self)
        return Tainted(result, self._source, (str(other)[:20],) + self._chain)

    def __mod__(self, other):
        return Tainted(str.__mod__(self, other), self._source, self._chain)

    def format(self, *args, **kwargs):
        return Tainted(str.format(self, *args, **kwargs), self._source, self._chain)

    def join(self, iterable):
        return Tainted(str.join(self, iterable), self._source, self._chain)

    def __repr__(self):
        return f"Tainted({super().__repr__()}, source={self._source!r})"
```

### 2.2 Source helpers

```python
# 工具层封装:任何外部源返回的字符串自动打 taint

def fetch_url(url: str) -> Tainted:
    response = httpx.get(url)
    return Tainted(response.text, source=f"http:{url}")

def read_email_body(msg) -> Tainted:
    return Tainted(msg.get_body().get_content(), source=f"email:{msg['Message-Id']}")

def read_uploaded_file(path: str) -> Tainted:
    return Tainted(open(path).read(), source=f"upload:{path}")
```

### 2.3 Sink 守卫

```python
class TaintViolation(Exception):
    """Raised when tainted data reaches a trust boundary it shouldn't cross."""

def assert_trusted(value: str, sink: str) -> str:
    """Gate function — call before passing data into a trusted sink."""
    if isinstance(value, Tainted):
        raise TaintViolation(
            f"Tainted data from {value.source!r} (chain={value.provenance}) "
            f"reached trusted sink {sink!r}. "
            f"Use a sanitizer (schema_extract / whitelist / human_confirm) first."
        )
    return value

# 在 P-LLM 封装里使用
def p_llm_call(prompt: str, tools: list) -> dict:
    assert_trusted(prompt, sink="p_llm.prompt")
    return llm.chat(prompt, tools=tools)

# 在工具参数里使用
def send_email(to: str, body: str):
    assert_trusted(to, sink="send_email.to")  # 收件人必须 trusted
    # body 可以是 Tainted —— 转发场景下保留原文是合理的
    smtp.send(to=to, body=str(body))
```

### 2.4 Sanitizer:三种合法去 taint 方式

```python
from pydantic import BaseModel

def schema_extract(tainted: Tainted, schema: type[BaseModel], llm) -> BaseModel:
    """让 Q-LLM 从 tainted 文本抽出 schema-bound 字段。返回值字段是 trusted。
    Q-LLM 失败 → 返回 None,绝不返回攻击者文本。"""
    try:
        result = llm.extract(str(tainted), response_format=schema)
        # 关键:result 的字符串字段是 plain str,taint 在 schema 抽取这一步被剥离
        return result
    except (ValidationError, RefusalError):
        return None

def whitelist_match(tainted: Tainted, allowed: set[str]) -> Optional[str]:
    """精确匹配白名单,命中返回白名单中的常量(trusted)。"""
    s = str(tainted)
    return s if s in allowed else None

def human_confirm(tainted: Tainted, question: str) -> Optional[str]:
    """用户在 UI 上确认 → 返回 trusted str;否则 None。
    Agent 框架要支持 confirmation event。"""
    if ui.confirm(question, preview=str(tainted)):
        return str(tainted)
    return None
```

### 2.5 关键参数注解

工具函数用 type hint + 装饰器声明哪些字段必须 trusted:

```python
from typing import Annotated

Trusted = Annotated[str, "must_be_trusted"]

@taint_aware
def send_email(
    to: Trusted,         # ← 必须 trusted,Tainted 类型直接抛
    subject: Trusted,    # ← 同上
    body: str,           # ← 可以 Tainted(原文转发常见)
):
    ...

@taint_aware
def http_request(
    url: Trusted,        # ← 防止 SSRF/exfil via URL
    method: Trusted,
    body: str,
):
    ...

@taint_aware
def execute_sql(
    query: Trusted,      # ← 防止 SQL 模板被 tainted 拼接
    params: tuple,       # ← params 可 tainted(参数化查询安全)
):
    ...
```

`@taint_aware` 装饰器在调用时检查所有 `Trusted` 注解的实参,Tainted 类型 → `TaintViolation`。

---

## 3. 与 dual-LLM 架构的对接

```python
def agent_step(user_input: str, mailbox):
    """处理"总结收件箱"任务的单步。"""

    # 1. user input 是 trusted(来自登录用户)
    plan = p_llm_call(
        f"User asked: {user_input}. Available tools: list_inbox, get_email, reply.",
        tools=[list_inbox, get_email, reply],
    )

    # 2. P-LLM 决定调 list_inbox
    inbox = list_inbox()  # 工具返回的元数据(发件人、主题)是 Tainted

    for email_meta in inbox:
        body = get_email(email_meta.id)  # Tainted

        # 3. Q-LLM 抽取
        summary = schema_extract(body, EmailSummary, q_llm)
        if summary is None:
            continue  # 抽取失败,跳过,不让攻击文本流回 P-LLM

        # 4. P-LLM 看 schema 字段(trusted)做决策
        next_plan = p_llm_call(
            f"Email summary: from={summary.sender_displayed}, "
            f"topic={summary.topic_one_line}, action={summary.requested_action}",
            tools=[reply, archive, flag],
        )

        # 5. 如果 P-LLM 决定 reply,收件人必须从 envelope 取(trusted)
        if next_plan.tool == "reply":
            reply(to=email_meta.envelope_from, body=...)
            # envelope_from 由邮件协议层提供,trusted;body 可 tainted
```

---

## 4. ember 落地

### 4.1 新增检测器

```python
# scanner/llm_app/taint_lint.py
@register
class TaintFlowDetector(Detector):
    name = "llm-taint-flow-violation"
    owasp = "LLM01:2025"
    severity = "high"

    def run(self, ctx):
        """静态扫描:
        - 找所有 Tainted source(http/file/email/upload)
        - 沿数据流找 sink(LLM client.chat、subprocess、SQL、send_email)
        - 没有经过 sanitizer 的路径 → 告警
        """
        for py_file in ctx.target_python_files():
            for flow in trace_taint_flow(py_file):
                if flow.has_sanitizer:
                    continue
                ctx.report({
                    "rule": self.name,
                    "severity": self.severity,
                    "location": flow.sink_location,
                    "message": f"Tainted data from {flow.source} reaches {flow.sink} "
                               f"without sanitization. Path: {flow.path}",
                })
```

实现路径:
- 用 `ast` + `jedi` 做局部数据流(MVP)
- 或上 `pysa`(Pyre 的 taint analyzer,Facebook 开源)做完整 interprocedural
- 先 MVP,真用户痛点出现再上 pysa

### 4.2 运行时模式

`assert_trusted` + `@taint_aware` 是**运行时**保护。ember 提供 `examples/dual_llm/taint.py`,LLM 应用开发者直接 import。

测试:
```python
# tests/test_taint.py
def test_tainted_string_propagates_through_concat():
    t = Tainted("hello", source="email:1")
    s = "prefix " + t + " suffix"
    assert isinstance(s, Tainted)
    assert "email:1" in s.provenance

def test_assert_trusted_raises_on_tainted():
    t = Tainted("evil", source="http:bad.com")
    with pytest.raises(TaintViolation):
        assert_trusted(t, sink="p_llm.prompt")

def test_schema_extract_strips_taint():
    t = Tainted('{"name": "Alice"}', source="upload:f.json")
    result = schema_extract(t, PersonSchema, mock_llm)
    assert not isinstance(result.name, Tainted)
```

---

## 5. 已知局限

| 局限 | 影响 | 缓解 |
|------|------|------|
| Python `str` 子类化在 C 扩展中会丢失类型 | numpy/pandas 处理后 taint 丢失 | 在工具层包装,Tainted 不进入数值库 |
| f-string 与 `.format()` 的混合用法静态难追 | 静态检测漏报 | 运行时 `assert_trusted` 兜底 |
| LLM 输出本身的 taint 状态 | P-LLM 输出可能被 Q-LLM 间接污染 | 输出层独立审计(URL 白名单、敏感字符串泄漏检测) |
| dict/list 容器无 taint 传播 | `{"key": tainted}["key"]` 返回 plain `Tainted`(类型保留),但 `json.dumps` 后丢失 | 提供 `TaintedDict` / 序列化 hook |
| 性能 | `Tainted.__add__` 比 str 慢 ~3× | 仅在 agent boundary 使用,核心循环不打 taint |

---

## 6. Next steps

1. **W1**:把上文 `taint.py` 全部实现 + 单测,放到 `examples/dual_llm/`
2. **W1**:`@taint_aware` 装饰器 + `Trusted` 注解类型
3. **W2**:`TaintFlowDetector` AST 版 MVP(覆盖 openai/anthropic SDK 的 chat 调用为 sink)
4. **W3**:对接 pysa 做完整数据流分析(可选)
5. **W3**:写 `examples/dual_llm/email_triage.py` 示范完整流程

---

## 参考文献

- Sabelfeld, A. & Myers, A. (2003). [Language-Based Information-Flow Security](https://www.cs.cornell.edu/andru/papers/jsac/sm-jsac03.pdf)
- Microsoft (2024). [TaskTracker: Detecting Prompt Injection Attacks via Task Drift](https://arxiv.org/abs/2406.00799)
- Costa, M. et al. (2024). [FIDES: Securing Compound AI Systems](https://arxiv.org/abs/2410.03182)
- Facebook (2020). [Pysa: Open-Sourcing Static Analysis for Python](https://engineering.fb.com/2020/08/07/security/pysa/)
