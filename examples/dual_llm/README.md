# Dual-LLM + Taint —— LLM 应用守侧防御参考实现

抄走即用的运行时防御原语,让你的 LLM agent 在处理不可信数据(网页/邮件/PDF/上传)时
**结构上抗 prompt injection**。设计与依据见 [`docs/defense/`](../../docs/defense/)。

> 这是**守侧**(保护你自己的应用),纯运行时库,零外部依赖(LLM 客户端用依赖注入传入)。

## 文件

| 文件 | 作用 |
|------|------|
| `taint.py` | 污点跟踪:`Tainted` 字符串 + `assert_trusted` sink 守卫 + `@taint_aware` + 三种 sanitizer |
| `injection_guard.py` | 透明启发式注入输入守卫(纵深防御最外层,**非**独立防御) |
| `jailbreak_guard.py` | 越狱框架识别(AML.T0054);只识别不生成,不含可用 payload |
| `perplexity_guard.py` | GCG 类对抗后缀(乱码)启发式拦截 |
| `query_budget.py` | 进程内查询/成本预算守卫(抗模型提取/成本耗尽/推理 DoS) |
| `q_llm.py` | Quarantined LLM:处理不可信数据,只输出 schema-bound 结构 |
| `p_llm.py` | Privileged LLM:唯一能调工具,prompt 必须 trusted(强制不变量 I2) |
| `tools.py` | 示例工具:关键参数用 `Trusted()` 注解(强制不变量 I4) |
| `email_triage.py` | 端到端示例:安全地"总结收件箱" |

## 核心思想

```
不可信数据 ──→ Tainted ──→ Q-LLM 抽成 schema 字段(去污点)──→ P-LLM 只看 trusted 字段 ──→ 工具
                    └── 直接拼进 P-LLM prompt? → assert_trusted 抛 TaintViolation
                    └── 当工具关键参数(收件人/URL)? → @taint_aware 抛 TaintViolation
```

5 条不变量(I1–I5)见 [`docs/defense/01-dual-llm-architecture.md`](../../docs/defense/01-dual-llm-architecture.md)。
最容易出错的是 **I4**:别把 Q-LLM 抽出来的 URL/收件人直接当下一步工具的关键参数(confused deputy)。

## 最小用法

```python
from taint import Tainted, assert_trusted, taint_aware, Trusted

# 外部数据打标记
body = Tainted(fetch_email_body(), source="email:42")

# 直接拼进 P-LLM → 抛异常
assert_trusted(body, sink="p_llm.prompt")   # TaintViolation

# 工具关键参数防线
@taint_aware
def send_email(to: Trusted(), body: str): ...
send_email(to=extracted_addr, body=body)     # extracted_addr 若 tainted → TaintViolation
```

## 定位(诚实)

- `injection_guard` 是签名启发式,会被改写绕过 —— 它只是最便宜的外层,**真正的边界是 dual-LLM + taint**。
- `taint.py` 的局限见 [`docs/defense/02-taint-tracking-framework.md`](../../docs/defense/02-taint-tracking-framework.md) §5(C 扩展丢类型、容器不传播等)。
- 这是参考实现,不是 SaaS 级产品;赢在**结构性防御 + 开源 + 可审计**。
