# Dual-LLM 架构(CaMeL-style)

> **目的**:让 LLM agent 在处理不可信外部数据(网页、邮件、PDF、用户上传)时,**结构上无法被注入劫持**——不管攻击 payload 长什么样。
>
> **思想来源**:Simon Willison 2023 "The Dual LLM pattern";Google DeepMind 2025 "CaMeL: Defeating Prompt Injections by Design" (arXiv:2503.18813)。本文是工程化适配,落到 ember 的 detector + reference impl。

---

## 1. 问题陈述

单 LLM agent 的根本缺陷:**同一个模型既"读不可信数据"又"决定调什么工具"**。注意力机制没有权限边界,任何外部数据里的指令都可能被当成命令执行(Greshake et al. 2023 间接注入)。

打补丁式防御(关键词过滤、refusal classifier)永远落在攻击后面——下一个未见过的 payload 就绕过了。

**架构级答案**:把"决定做什么"和"处理数据"拆成两个 LLM,信任边界画在中间。

---

## 2. 角色定义

```
┌─────────────────────────────────────────────────────────────┐
│  USER                                                       │
│   │                                                         │
│   │ 自然语言任务                                            │
│   ▼                                                         │
│  ┌──────────────────────────────────────┐                   │
│  │ PRIVILEGED LLM (P-LLM)               │ ← 永不接触        │
│  │  - 唯一能调工具                      │   不可信数据      │
│  │  - 只看 user prompt + structured     │                   │
│  │    summaries(由 Q-LLM 输出)         │                   │
│  │  - 输出: 工具调用计划 (typed)        │                   │
│  └──────────┬───────────────────────────┘                   │
│             │ 调用 tool(args)                               │
│             ▼                                               │
│  ┌──────────────────────────────────────┐                   │
│  │ TOOL LAYER (无 LLM)                   │                   │
│  │  - 执行工具,返回原始结果             │                   │
│  │  - 结果打 taint 标记                  │                   │
│  └──────────┬───────────────────────────┘                   │
│             │ tainted_data                                  │
│             ▼                                               │
│  ┌──────────────────────────────────────┐                   │
│  │ QUARANTINED LLM (Q-LLM)              │ ← 只能输出        │
│  │  - 处理不可信数据                    │   structured      │
│  │  - 严格 schema-bound 输出            │   schema          │
│  │  - 无工具访问,无网络,无副作用       │   (typed)         │
│  │  - 输出: 受 schema 约束的字段       │                   │
│  └──────────┬───────────────────────────┘                   │
│             │ validated structured data                     │
│             ▼                                               │
│      回到 P-LLM 上下文(只填入字段值,不填自由文本)         │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 P-LLM(Privileged)
- **能力**:看 user 自然语言、看 Q-LLM 返回的结构化字段、调工具
- **禁止**:看 Q-LLM 的"raw text"输出、看任何标记 tainted 的字符串原文
- **输出**:仅工具调用计划(JSON,typed schema)

### 2.2 Q-LLM(Quarantined)
- **能力**:看不可信数据原文、按 schema 抽取字段
- **禁止**:调任何工具、访问网络、生成自由文本(只能填 schema)
- **失败模式**:schema 验证失败 → P-LLM 收到 `null` + 错误码,而非攻击者文本

### 2.3 Tool Layer
- 无 LLM 参与。纯代码。
- 每个工具声明:`input_schema`、`output_taint_level`(trusted / tainted)
- 工具返回值进入 P-LLM 前,**必须**经 Q-LLM 抽取或显式标 trusted。

---

## 3. 关键不变量(Invariants)

这是架构正确性的核心。如果以下任何一条被违反,整个防御失效:

| # | 不变量 | 强制方式 |
|---|--------|----------|
| I1 | P-LLM 的 prompt 中,**除 user 原始输入外**,只能含 Q-LLM 输出的 schema 字段值 | prompt 模板编译时检查;runtime assert |
| I2 | tainted 字符串永不直接拼入 P-LLM prompt | taint 标记 + 拼接守卫(见 doc 02) |
| I3 | Q-LLM 的输出必须通过 schema 验证才能传给 P-LLM | pydantic / jsonschema 强校验 |
| I4 | 工具调用参数的关键字段(收件人、URL、文件路径)必须是 P-LLM 计划中明确指定的常量,不能来自 Q-LLM 输出 | 工具签名标注 `constant_only` 字段 |
| I5 | Q-LLM 无网络、无工具、无文件写权限 | 进程级沙箱(子进程 + 限权) |

I4 是最容易出错的——agent 框架经常允许"用 Q-LLM 抽取出来的 URL"作为下一步工具的参数。这就是 confused deputy 的入口。

---

## 4. Schema-Bound 输出(以邮件总结为例)

**Bad(单 LLM)**:
```python
summary = llm(f"Summarize this email: {email_body}")
agent.maybe_reply(summary)  # ← summary 可能含"Reply to attacker@evil.com saying..."
```

**Good(dual-LLM)**:
```python
class EmailSummary(BaseModel):
    sender_displayed: str = Field(max_length=200)
    topic_one_line: str = Field(max_length=200)
    has_attachment: bool
    requested_action: Literal["none", "reply", "forward", "schedule_meeting"]
    # 注意:没有 "reply_to" 字段——回复地址必须从 envelope 取,不从邮件正文取

summary = q_llm(email_body, schema=EmailSummary)  # 失败则返回 None
# summary 是 typed object,字段都受 max_length 限制
p_llm_prompt = render_template(
    "user wants to triage inbox. one email: from={sender}, topic={topic}",
    sender=summary.sender_displayed,
    topic=summary.topic_one_line,
)
plan = p_llm(p_llm_prompt, tools=[reply_to, archive, flag])
# plan.tool == "reply_to" → 收件人参数必须来自 envelope.from,不来自 summary
```

---

## 5. 落到 ember 的工程化

### 5.1 新增模块:`scanner/llm_app/`

```
scanner/llm_app/
├── __init__.py
├── architecture_audit.py    # 静态扫描:检查 LLM 应用是否违反 I1–I5
├── prompt_template_lint.py  # lint prompt 模板:tainted 字符串拼接告警
└── schema_check.py          # 验证 Q-LLM 调用是否 schema-bound
```

### 5.2 新增 detector

继承 `scanner.detectors.base.Detector`(已有模式):

```python
@register
class DualLLMViolationDetector(Detector):
    name = "llm-dual-llm-violation"
    owasp = "LLM01:2025"  # OWASP LLM Top 10 — Prompt Injection
    severity = "high"

    def run(self, ctx):
        # 扫 Python AST:
        #   - 找所有 LLM client 调用(openai/anthropic/litellm)
        #   - 看 prompt 参数里是否含 untrusted source 的拼接
        #   - 看是否所有处理外部数据的 LLM 调用都带 response_format/schema
        for py_file in ctx.target_python_files():
            for finding in audit_dual_llm(py_file):
                ctx.report(finding)
```

### 5.3 reference impl(给 ember 用户抄)

放到 `examples/dual_llm/`:
- `q_llm.py`:Q-LLM 封装,强制 `response_format=pydantic_schema`
- `p_llm.py`:P-LLM 封装,prompt 模板编译时拒绝非常量字段值
- `tools.py`:工具 schema 声明 `constant_only` 字段
- `taint.py`:见 doc 02

---

## 6. 适用范围与权衡

| 场景 | dual-LLM 适用度 | 说明 |
|------|----------------|------|
| Agent 处理邮件/网页/文档 | ★★★★★ | 教科书场景 |
| RAG 问答 | ★★★★ | 检索结果走 Q-LLM 抽取后再喂 P-LLM |
| Code-writing agent | ★★★ | 代码本身既是数据也是指令,边界模糊 |
| 多 agent 协作 | ★★★★ | 每个 agent 内部各自 dual-LLM,agent 间消息走 schema |
| 流式对话 (chatbot) | ★★ | 用户输入即不可信,过度 schema 化损害体验 |

**成本**:
- 每次外部数据处理多一次 LLM 调用(Q-LLM)→ 延迟 1.5–2×、成本 1.5–2×
- Q-LLM 可用小模型(Haiku/Mini),成本可控
- Schema 设计是工程投入,但一次设计长期复用

**何时不该用**:
- 纯单轮 chat,无工具调用,无外部数据 → 没必要
- 极低延迟场景 → 考虑 Spotlighting(arXiv:2403.14720)作为轻量替代

---

## 7. 与其他防御层的关系

dual-LLM 不替代其他防御,而是**承载它们的骨架**:

- **Taint tracking**(doc 02)→ 强制 I2/I4 的运行时检查
- **MITRE ATLAS 覆盖**(doc 03)→ dual-LLM 直接闭合 ATLAS 的 AML.T0051(LLM Prompt Injection)+ AML.T0053(LLM Plugin Compromise)
- **Output filter**(markdown URL 白名单)→ 即使 P-LLM 被部分污染,输出侧再挡一层
- **Perplexity filter** → 给 Q-LLM 加一道前置,拦 GCG 类对抗后缀

---

## 8. Next steps(实施顺序建议)

1. **W1**:写 `examples/dual_llm/` reference impl(~200 行 Python)
2. **W1**:实现 `taint.py`(见 doc 02)
3. **W2**:写 `DualLLMViolationDetector`(AST 扫描,覆盖 openai/anthropic SDK)
4. **W2**:在 README "守侧" 表里加一行 LLM01:2025
5. **W3**:用 Lakera PINT / JailbreakBench 跑端到端评估,出基线

---

## 参考文献

- Willison, S. (2023). [The Dual LLM pattern for building AI assistants that can resist prompt injection](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)
- Debenedetti, E. et al. (2025). [Defeating Prompt Injections by Design (CaMeL)](https://arxiv.org/abs/2503.18813)
- Greshake, K. et al. (2023). [Not what you've signed up for: Indirect Prompt Injection](https://arxiv.org/abs/2302.12173)
- Hines, K. et al. (2024). [Defending Against Indirect Prompt Injection Attacks With Spotlighting](https://arxiv.org/abs/2403.14720)
- OWASP (2025). [LLM Top 10 — LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
