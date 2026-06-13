# MITRE ATLAS 覆盖对照表

> **目的**:把 ember 现有 18 个守侧检测器映射到 MITRE ATLAS(AI 系统专用 ATT&CK 矩阵),找出**真实威胁覆盖缺口**,排出实施优先级。
>
> **结论先说**:ember 当前覆盖的是 OWASP API Top 10(传统 Web/API 层),**ATLAS 上的 LLM 应用层威胁完全未覆盖**——这是真正要补的部分。下面有详细分级。
>
> **数据源**:[MITRE ATLAS](https://atlas.mitre.org/) 矩阵 v2025;ember `scanner/detectors/` 全量审计。

---

## 1. ATLAS 简介(对照 ATT&CK)

| 维度 | ATT&CK | ATLAS |
|------|--------|-------|
| 范围 | 企业 IT 系统 | AI/ML 系统 |
| 战术(Tactics) | 14 个 | 14 个,含 ML 特有 |
| 技术(Techniques) | 数百 | ~80,持续扩展 |
| 适配场景 | 主机/网络入侵 | 模型投毒、推理攻击、prompt injection、agent 滥用 |

ATLAS 的特殊价值:**把"模型作为攻击面"系统化**——这是 OWASP API/Web Top 10 完全没有的视角。

---

## 2. ember 现有 18 个检测器全量列表

| Detector name | OWASP API | Severity | 文件 |
|---|---|---|---|
| `mass-assignment` | API6:2023 | high | access_control.py |
| `graphql-introspection` | API9:2023 | medium | exposure.py |
| `debug-exposure` | API8:2023 | medium | exposure.py |
| `http-method` | API8:2023 | low | exposure.py |
| `verbose-errors` | API8:2023 | low | exposure.py |
| `jwt-alg-none` | API2:2023 | critical | jwt.py |
| `jwt-unsigned` | API2:2023 | critical | jwt.py |
| `jwt-sig-not-verified` | API2:2023 | critical | jwt.py |
| `open-redirect` | API7:2023 | medium | redirect.py |
| `host-header` | API8:2023 | medium | redirect.py |
| `ssrf` | API7:2023 | high | ssrf.py |
| `auth-bypass` | API2:2023 | high | legacy.py |
| `ops-escalate` | API5:2023 | critical | legacy.py |
| `rate-bypass` | API4:2023 | medium | legacy.py |
| `idor` | API1:2023 | high | legacy.py |
| `info-leak` | API3:2023 | medium | legacy.py |
| `sec-headers` | API8:2023 | medium | legacy.py |
| `cors` | API8:2023 | high | legacy.py |

---

## 3. ATLAS → ember 对照(诚实版本)

### 3.1 ember 现有检测器对 ATLAS 的间接贡献

ember 现有检测器主要打击的是**承载 AI 应用的 Web 基础设施**——所以对 ATLAS 中"经传统 Web 路径攻击 AI"的技术有间接覆盖。

| ATLAS Technique | 描述 | ember 覆盖 | 贡献度 |
|---|---|---|---|
| **AML.T0049** Exploit Public-Facing Application | 通过 Web 漏洞拿到 AI 服务的初始访问 | `ssrf`, `auth-bypass`, `jwt-*`, `idor`, `mass-assignment` | ★★★★ 直接 |
| **AML.T0040** ML Model Inference API Access | 拿到模型推理 API 访问权 | `auth-bypass`, `jwt-*`, `rate-bypass`, `idor` | ★★★ 间接 |
| **AML.T0024.000** Infer Training Data Membership | 通过推理 API 滥用做成员推理 | `rate-bypass` | ★ 仅速率限制层 |
| **AML.T0024.001** Invert ML Model | 通过 API 滥用做模型反演 | `rate-bypass` | ★ 仅速率限制层 |
| **AML.T0029** Denial of ML Service | 资源耗尽攻击 | `rate-bypass` | ★★ 部分 |
| **AML.T0034** Cost Harvesting | 让目标产生高昂推理成本 | `rate-bypass` | ★★ 部分 |
| **AML.T0044** Full ML Model Access | 模型权重外泄/侧信道 | `info-leak`, `debug-exposure`, `verbose-errors` | ★★ 部分 |

**翻译**:ember 现在能在"AI 服务的 Web 外壳"层提供基础保护,但**模型/agent/prompt 层的攻击它完全不知道**。

### 3.2 ATLAS 上的 LLM 关键技术 — 当前**零覆盖**

这是真正的工作清单。每行都是 ember 应该补上的检测器:

| Priority | ATLAS Technique | 攻击描述 | 建议 detector | 工程量 |
|---|---|---|---|---|
| **P0** | **AML.T0051.000** LLM Prompt Injection: Direct | 用户输入里塞"忽略上面"类指令 | `llm-prompt-injection-direct`(已有公开 corpus:[Lakera PINT](https://github.com/lakeraai/pint-benchmark)) | S |
| **P0** | **AML.T0051.001** LLM Prompt Injection: Indirect | 网页/邮件/PDF 里藏指令,agent 读取后执行 | `llm-indirect-injection-sink`(扫 agent 是否净化外部数据) | M |
| **P0** | **AML.T0053** LLM Plugin Compromise | 第三方插件/工具被滥用做攻击者意图 | `llm-tool-confused-deputy`(静态扫:外部数据是否能流到 tool 参数) | M |
| **P0** | **AML.T0057** LLM Data Leakage | 通过 prompt/输出外泄敏感数据(含 markdown img exfil) | `llm-output-exfil`(扫输出层:markdown URL 白名单、敏感字符串检测) | S |
| **P1** | **AML.T0054** LLM Jailbreak | DAN、Crescendo、PAIR、GCG 等绕过 alignment | `llm-jailbreak-input`(对接 [JailbreakBench](https://jailbreakbench.github.io/))+ `llm-perplexity-filter`(拦 GCG) | M |
| **P1** | **AML.T0050** Command and Scripting Interpreter | LLM 生成代码并被自动执行,变成 RCE 入口 | `llm-code-exec-sandbox`(扫:LLM 输出的代码是否进入 `eval`/`exec`/subprocess) | M |
| **P1** | **AML.T0048.000–004** External Harms (Financial/Reputational/User/Societal) | LLM 应用对用户/社会的实际伤害 | 评估框架而非单 detector,加 `examples/harm_eval/` 模板 | L |
| **P2** | **AML.T0061** LLM Prompt Self-Replication | Agent A 把恶意 prompt 注入到给 Agent B 的消息里(蠕虫) | `llm-multi-agent-message-audit` | L |
| **P2** | **AML.T0024.002** Extract ML Model | 通过大量查询提炼模型/权重 | `llm-query-budget-anomaly`(用量异常告警) | M |
| **P2** | **AML.T0043** Craft Adversarial Data | 对抗样本(主要针对视觉模型) | 暂缓,等用户需求 | — |
| **P3** | **AML.T0018** Backdoor ML Model | 训练时植入后门 | 检测域外,做 supply-chain 文档替代 | — |
| **P3** | **AML.T0020** Poison Training Data | 训练数据投毒 | 同上 | — |

工程量记号:S = 1–2 天,M = 3–5 天,L = > 1 周。

---

## 4. 推荐实施波次(Roadmap)

### Wave 1(2 周内可上线):闭合 ATLAS Initial Access + Defense Evasion 层
基于 doc 01 / doc 02 的架构 + 4 个 P0 detector:
- `llm-prompt-injection-direct`(输入侧分类器,用 Lakera PINT 训)
- `llm-indirect-injection-sink`(AST:扫外部数据是否过净化器)
- `llm-output-exfil`(输出侧:markdown URL 白名单 + 敏感字符串泄漏检测)
- `llm-tool-confused-deputy`(AST:外部数据 → tool 关键参数的数据流)

→ ATLAS 覆盖:T0051.000, T0051.001, T0053, T0057

### Wave 2(1 个月内):闭合 Jailbreak + Code Exec
- `llm-jailbreak-input`(对接 JailbreakBench,4 个家族:DAN/Crescendo/PAIR/GCG)
- `llm-perplexity-filter`(GCG 后缀拦截,~50 行)
- `llm-code-exec-sandbox`(扫 LLM 输出代码是否进 `eval`/`exec`)

→ ATLAS 覆盖:T0054, T0050

### Wave 3(按需):多 agent + 滥用监测
- `llm-multi-agent-message-audit`
- `llm-query-budget-anomaly`(运行时 metric,需要接 Prometheus)
- harm evaluation framework(`examples/harm_eval/`)

→ ATLAS 覆盖:T0061, T0024.002, T0048.*

---

## 5. ATLAS Mitigations 对照

ATLAS 也给出标准缓解(`AML.M0xxx`)。ember 当前/规划的能力对应如下:

| ATLAS Mitigation | ember 实现 |
|---|---|
| AML.M0000 Limit Public Release of Information | `info-leak`, `debug-exposure`, `verbose-errors`(已有) |
| AML.M0004 Restrict Number of ML Model Queries | `rate-bypass`(已有) |
| AML.M0015 Adversarial Input Detection | Wave 1: `llm-prompt-injection-direct`;Wave 2: `llm-jailbreak-input`, `llm-perplexity-filter` |
| AML.M0017 Model Distribution Methods | 文档(supply chain 章节) |
| AML.M0018 User Training | examples + README "agent 开发者注意事项" |
| AML.M0019 Control Access to ML Models and Data | `auth-bypass`, `idor`, `mass-assignment`(已有) |

---

## 6. 报告输出建议

ember 的 SARIF 输出(`scanner/sarif.py`)目前只带 OWASP 标签。建议每个新 detector 同时声明 ATLAS technique:

```python
@register
class IndirectInjectionDetector(Detector):
    name = "llm-indirect-injection-sink"
    owasp = "LLM01:2025"
    atlas = "AML.T0051.001"      # ← 新增字段
    atlas_mitigation = "AML.M0015"
    severity = "high"
```

SARIF reportingDescriptor 里把 atlas 放进 `properties.tags`,供 Splunk/Sentinel 这类 SIEM 直接消费。

---

## 7. 与公开行业基线对比

我看了主流 LLM 安全工具(Lakera Guard、Rebuff、NeMo Guardrails、Garak、PromptArmor)的公开技术页:

| 工具 | 侧重 | ember 差异定位 |
|---|---|---|
| Lakera Guard | 输入侧分类器(SaaS) | ember 是自部署 + 含架构静态扫描 |
| Rebuff | 输入侧 canary + heuristic | ember 覆盖更广(含 agent 工具链) |
| NeMo Guardrails | DSL 控制对话流 | ember 不替代,可互补 |
| Garak | LLM 漏洞 fuzzer(类似 nmap) | ember 守侧 = 防御端;Garak 攻侧扫漏洞 |
| PromptArmor | 商业输入/输出过滤 | ember 开源 + 架构层(dual-LLM) |

**ember 的差异化主张**:**架构级 + 守侧专一 + 开源 + 中文一线工程实战**。不和 SaaS 拼 ML 分类器精度,赢在结构性防御(dual-LLM + taint)+ 静态扫描能力。

---

## 8. 行动项汇总

| # | 任务 | 关联 doc | Owner | 时间 |
|---|---|---|---|---|
| 1 | 实现 `examples/dual_llm/` reference impl | doc 01 | TBD | W1 |
| 2 | 实现 `taint.py` + 单测 | doc 02 | TBD | W1 |
| 3 | 写 `llm-prompt-injection-direct` detector + Lakera PINT 基线 | doc 03 P0 | TBD | W1 |
| 4 | 写 `llm-indirect-injection-sink` AST detector | doc 03 P0 | TBD | W2 |
| 5 | 写 `llm-output-exfil` detector | doc 03 P0 | TBD | W2 |
| 6 | 写 `llm-tool-confused-deputy` AST detector | doc 03 P0 | TBD | W2 |
| 7 | SARIF 输出加 ATLAS 字段 | doc 03 §6 | TBD | W2 |
| 8 | Wave 2:jailbreak + perplexity + code-exec | doc 03 Wave 2 | TBD | W3–4 |

---

## 参考

- MITRE ATLAS Matrix: <https://atlas.mitre.org/matrices/ATLAS>
- MITRE ATLAS Case Studies: <https://atlas.mitre.org/studies>
- OWASP LLM Top 10 (2025): <https://genai.owasp.org/llm-top-10/>
- Lakera PINT Benchmark: <https://github.com/lakeraai/pint-benchmark>
- JailbreakBench: <https://jailbreakbench.github.io/>
- HarmBench: <https://www.harmbench.org/>
