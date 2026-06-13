# 🔥 Ember

> AI systems burn bright but hide their fire. Ember reads the ash.

五层攻防一体的安全工具包。基于 [CL4R1T4S](https://github.com/elder-plinius/CL4R1T4S) (29.5k ★) 泄露的全部 AI 系统 prompt + OWASP Top 10 + 绿洲 18 模块生产实战经验构建。

**守**: 对自己的 API/网络/主机做全自动漏洞扫描，一键出 HTML 报告。
**攻**: AI 注入引擎内含 5 类提取技术 + 5 模型绕过技巧库，基于 Pliny 社区验证过的真实攻击手法。

## 安装

守侧扫描器可作为独立 CLI 安装(只打包守侧,不含攻侧):

```bash
pipx install git+https://github.com/exergyleizhou-ux/ember.git
ember-scan --target http://localhost:8080/api/v1
```

或从源码:

```bash
git clone https://github.com/exergyleizhou-ux/ember.git && cd ember
pip install -e .            # 装出 ember-scan 命令
```

## 快速开始

```bash
git clone https://github.com/exergyleizhou-ux/ember.git
cd ember

# 一键全扫描
python3 run.py --target http://localhost:8080/api/v1

# 全量 (含 payload 注入 + 网络 + AI 攻击面矩阵)
python3 run.py --target https://your-server.com/api/v1 --full

# 只看 AI 攻击面 (黑客知识库)
python3 ai/inject.py --matrix

# 生成针对 Claude 的注入脚本
python3 ai/inject.py -t role-reversal -m Claude

# 🔥 红队模式 — 一键解放: 攻击面分析 + 最佳 payload + 实弹扫描
python3 run.py -t http://target:8080/api/v1 --liberation -m Claude

# 查看 Claude 的攻击链推理
python3 ai/prompt_library.py -m Claude
```

## 红队模式示例

```bash
$ python3 ai/prompt_library.py -m Claude

🎯 Claude → anthropic
   Payload 总数: 84
   分类分布: {'general_injection': 3, 'system_extraction': 1, 'own_server_pretext': 1}

📋 策略: Claude: decomposition + academic framing + 'own server' pretext.

🧠 推理:
   Fable 5 的 9 条拒绝规则中,对'恶意代码'的拒绝(CRITICAL)接受一个关键例外:
   '自己的服务器渗透测试'属于允许范围。Claudeception 攻击面(Artifact API 用 Sonnet 4)
   是二级绕过路径——让 Fable 5 生成调用 Sonnet 4 的代码,Sonnet 4 安全约束更弱。
   武器库中有 84 条 Anthropic 专用 payload。

🔗 攻击链:
   1. Recon: 建立学术/安全研究上下文 (Fable 5 对'自己资产'的测试放行)
   2. Decompose: 把攻击目标拆成学术子问题,避开 'malware/exploit' 关键词
   3. Inject: 用角色反转 payload 让 Claude 以为自己在做合规审计
   4. Verify: 检查是否触发 cyber_warning / ethics_reminder
```

## 七层攻防

| 层 | 模块 | 能力 |
|----|------|------|
| **API 扫描** | `scanner/scanner.py` | 鉴权绕过 · 权限提升 · 限流缺失 · IDOR · 信息泄露 |
| **Payload 注入** | `payloads/engine.py` | SQLi (10) · XSS (9) · JWT (3) · PathTraversal (8) · SSRF (7) |
| **网络扫描** | `network/scan.py` | SSL/TLS 弱加密检测 · 端口暴露扫描 (PG/Redis/SSH) |
| **AI 防火墙** | `ai/probe.py` | 6 模型禁止话题对比 · probe 预测 · 共同盲点检测 |
| **AI 注入引擎** | `ai/inject.py` | 5 类注入技术 · 每模型绕过技巧库 · 攻击面矩阵 |
| **L1B3RT4S 兵器库** | `ai/prompt_library.py` | 387 payload (39厂) · 关键词检索 · 攻击链推理 |
| **Fable 5 武器化** | `ai/fable5.py` | 120KB prompt 解析 · 9 拒绝规则 · Claudeception 攻击面 |

## 项目结构

```
ember/
├── run.py              ← 统一启动器，一键出 HTML 报告
├── scanner/            ← API 安全扫描引擎
├── payloads/           ← SQLi/XSS/JWT/PathTrav/SSRF 注入库
├── network/            ← SSL/TLS + 端口扫描
├── ai/
│   ├── probe.py        ← AI 防火墙探测器
│   ├── inject.py       ← AI 注入引擎 (5 类技术)
│   ├── fable5.py       ← Fable 5 武器化解析器
│   ├── prompt_library.py ← 387 payload 兵器库
│   └── scrape_l1b3rt4s.py ← L1B3RT4S 同步工具
├── reports/            ← JSON 扫描报告
└── html/               ← HTML 可视化报告
```

## 授权护栏

所有扫描入口(`run.py` / `scanner/scanner.py`)在动手前都会强制授权检查:
本机(localhost/127.0.0.1)始终放行,**其它目标必须用 `--scope` 显式声明授权**,
否则直接拒绝并退出。未授权扫描在多数司法辖区违法 —— 这条护栏从结构上防手滑。

```bash
# 本机自测:无需 --scope
python3 run.py -t http://localhost:8080/api/v1

# 远程目标:必须显式授权(且你需持有书面授权)
python3 run.py -t https://staging.example.com/api/v1 --scope example.com
```

## 生产特性(守侧)

```bash
# 限速防打挂 + 连接重试 + SARIF 输出(供 GitHub Code Scanning)
python3 scanner/scanner.py -t http://localhost:8080/api/v1 \
    --rate 20 --retries 3 --sarif reports/ember.sarif --verbose
```

- `--rate N` 每秒最多 N 次请求(0=不限),`--retries N` 连接失败退避重试
- `--sarif PATH` 输出 SARIF 2.1.0,可直接接 CI / GitHub Code Scanning
- `--verbose` 打印每次请求的 debug 日志

## 测试 & CI

守侧(扫描器/注入引擎/网络)带完整测试,用纯标准库靶机端到端验证
"已知漏洞必检出、健康端点不误报",并覆盖授权护栏、限速/重试、SARIF、全链路冒烟:

```bash
pip install -e ".[dev]"
pytest -q          # 62 个测试
ruff check scanner payloads network run.py tests
```

CI(`.github/workflows/ci.yml`)在每个 PR 上跑 Python 3.9/3.12 的 ruff + pytest。

## 为什么叫 Ember

Pliny 的项目叫 CL4R1T4S（Claritas，拉丁语 "清晰"）。Ember 是余烬——不张扬，但持续燃烧。AI 公司不愿让你看见的指令藏在火焰背后，Ember 读灰烬里的真相。
