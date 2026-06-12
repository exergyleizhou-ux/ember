# 🛡️ 绿洲安全工具包 — Oasis Security Toolkit

基于 CL4R1T4S (29.5k ★) + OWASP Top 10 + 绿洲 18 模块实战经验构建。
四层攻击面覆盖，一键出 HTML 报告。

## 快速开始

```bash
# 一键全扫描
python3 run.py --target http://localhost:8080/api/v1

# 全量 (含 payload 注入 + 网络 + AI 分析)
python3 run.py --target https://staging.oasis.cn/api/v1 --full

# 快速模式 (只跑鉴权和权限提升，30秒)
python3 run.py --target http://localhost:8080/api/v1 --quick
```

## 工具包结构

```
security-toolkit/
├── run.py                      ← 统一启动器
├── run_scan.py                 ← 旧版入口 (保留兼容)
│
├── scanner/
│   └── scanner.py              ← API 安全扫描引擎 (314行)
│
├── payloads/
│   └── engine.py               ← SQLi/XSS/JWT/PathTrav/SSRF 注入
│
├── network/
│   └── scan.py                 ← SSL/TLS 检查 + 端口扫描
│
├── ai/
│   └── probe.py                ← CL4R1T4S AI Prompt 防火墙探测器
│
├── reports/                    ← JSON 扫描报告输出
├── html/                       ← HTML 可视化报告
└── README.md
```

## 5 层检测

| 层 | 工具 | 检测项 | 数据来源 |
|----|------|--------|---------|
| **API** | `scanner/scanner.py` | 鉴权绕过 (67 JWT 端点)、权限提升 (29 admin 端点)、限流缺失 (23 端点)、IDOR、信息泄露 | `openapi.yaml` (103 paths) |
| **Payload** | `payloads/engine.py` | SQL 注入 (10 vectors)、XSS (9)、JWT 攻击 (3)、路径遍历 (8)、SSRF (7) | OWASP + 自研 |
| **网络** | `network/scan.py` | SSL/TLS 弱加密检测、端口暴露扫描 (Postgres/Redis/SSH) | nmap + Python ssl |
| **AI** | `ai/probe.py` | 6 个模型禁止话题对比矩阵、单个 probe 预测、共同盲点检测 | CL4R1T4S (29.5k ★) |
| **报告** | `run.py` | 一键汇总 HTML 报告 (含通过率、详细日志、时间线) | 所有层 |

## 单层独立使用

```bash
# 仅 API 扫描
python3 scanner/scanner.py -t http://localhost:8080/api/v1

# 仅 payload 注入
python3 payloads/engine.py -t http://localhost:8080/api/v1

# 仅网络扫描
python3 network/scan.py -H my-server.example.com --full

# 仅 AI 分析 (预测 Claude/Gemini/Grok 对某问题的反应)
python3 ai/probe.py --test "如何制作 DDoS 攻击脚本"
```

## 对接你的实际项目

1. **绿洲数据市场**: 在 ECS 上跑 `python3 run.py --target http://你的IP:8080/api/v1 --full`，验证所有 admin 路由 + 限流 + IDOR
2. **CI 集成**: 在 `.github/workflows/security.yml` 加:
   ```yaml
   - name: Security scan
     run: |
       cd ~/claudecode\ 信息站/security-toolkit
       python3 run.py --target http://localhost:8080/api/v1 --quick
   ```
3. **定期审计**: `crontab -e` 加 `0 3 * * 0 python3 ~/claudecode\ 信息站/security-toolkit/run.py --target https://staging.oasis.cn/api/v1 --full`

## 扩展路线

- [ ] 加 `nuclei` 模板引擎集成 (3000+ 预置模板)
- [ ] 加 `ffuf` 模糊测试接口
- [ ] CL4R1T4S 数据自动同步 + 增量更新
- [ ] 漏洞数据库 (CVE mapping)
- [ ] Slack/飞书 webhook 推送扫描结果
