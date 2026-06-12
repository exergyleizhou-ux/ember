# 🔥 Ember

> AI systems burn bright but hide their fire. Ember reads the ash.

五层攻防一体的安全工具包。基于 [CL4R1T4S](https://github.com/elder-plinius/CL4R1T4S) (29.5k ★) 泄露的全部 AI 系统 prompt + OWASP Top 10 + 绿洲 18 模块生产实战经验构建。

**守**: 对自己的 API/网络/主机做全自动漏洞扫描，一键出 HTML 报告。
**攻**: AI 注入引擎内含 5 类提取技术 + 5 模型绕过技巧库，基于 Pliny 社区验证过的真实攻击手法。

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
```

## 五层检测

| 层 | 模块 | 能力 |
|----|------|------|
| **API 扫描** | `scanner/scanner.py` | 鉴权绕过 · 权限提升 · 限流缺失 · IDOR · 信息泄露 |
| **Payload 注入** | `payloads/engine.py` | SQLi (10) · XSS (9) · JWT (3) · PathTraversal (8) · SSRF (7) |
| **网络扫描** | `network/scan.py` | SSL/TLS 弱加密检测 · 端口暴露扫描 (PG/Redis/SSH) |
| **AI 防火墙** | `ai/probe.py` | 6 模型禁止话题对比 · probe 预测 · 共同盲点检测 |
| **AI 注入引擎** | `ai/inject.py` | 5 类注入技术 · 每模型绕过技巧库 · 攻击面矩阵 · 可执行注入脚本生成 |

## 项目结构

```
ember/
├── run.py              ← 统一启动器，一键出 HTML 报告
├── scanner/            ← API 安全扫描引擎
├── payloads/           ← SQLi/XSS/JWT/PathTrav/SSRF 注入库
├── network/            ← SSL/TLS + 端口扫描
├── ai/
│   ├── probe.py        ← AI Prompt 防火墙探测器
│   └── inject.py       ← AI Prompt 注入引擎 (5 类技术)
├── reports/            ← JSON 扫描报告
└── html/               ← HTML 可视化报告
```

## 为什么叫 Ember

Pliny 的项目叫 CL4R1T4S（Claritas，拉丁语 "清晰"）。Ember 是余烬——不张扬，但持续燃烧。AI 公司不愿让你看见的指令藏在火焰背后，Ember 读灰烬里的真相。
