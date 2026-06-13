# Changelog

本项目的显著变更记录于此。版本遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 检测器注册表(P0,为 OWASP API Top 10 覆盖铺路)
- 新增插件化检测器注册表(`scanner/detectors/`):每个检测器是声明 name/owasp/severity、
  实现 `run(ctx)` 的小类,自动注册。现有 7 项检查(auth-bypass/ops-escalate/rate-bypass/
  idor/info-leak/sec-headers/cors)迁入注册表,**行为不变,76 测试全绿**。
- `scanner.py` 瘦身为:装 spec → 建 ScanContext → 跑注册表 → 报告/SARIF。
- 新 CLI:`--list-detectors`(列出 name/OWASP/severity)、`--enable`/`--disable` 按名启停。
- 见设计 `docs/superpowers/specs/2026-06-13-detector-registry-design.md`。

## [Unreleased-prev] — 守侧生产化

把"守"(防守 / 授权扫描)侧从"能跑"推到生产成熟。**仅守侧;攻侧(ai/ web/ exploits/)未触碰。**

### Added
- **测试基建**:纯标准库、可开关漏洞的靶机(`tests/fixtures/vulnerable_target.py`),
  62 个测试覆盖 5/5 检测器(端点分类、`_analyze` 判定、报错型/时间盲注 SQLi、
  AUTH-BYPASS、OPS-ESCALATE、IDOR),每个都双向验证"漏洞开→检出、漏洞关→不误报"。
- **授权护栏**(`scanner/scope.py`):本机始终放行,远程目标必须 `--scope` 显式授权,
  否则拒绝并以非零退出。接入 `scanner.py` 与 `run.py`。
- **SARIF 2.1.0 输出**(`scanner/sarif.py`,`--sarif`):供 CI / GitHub Code Scanning。
- **运行质量**:限速 `--rate`(防打挂目标)、退避重试 `--retries`(扛网络抖动)、
  日志 `--verbose`。
- **可分发**:守侧打包为 pip/pipx 可安装,暴露 `ember-scan` 命令(攻侧排除在分发物外)。
- **CI**(`.github/workflows/ci.yml`):Python 3.9/3.12 上跑 ruff + pytest + 入口点冒烟。

- **新检测**(`scanner/web_checks.py`):安全响应头缺失(HSTS/CSP/X-Content-Type-Options/
  X-Frame-Options)与 CORS 配置(回显任意 Origin、`*`+凭证)。被动检查,不发攻击 payload。
- **授权扫描工作流**(`.github/workflows/authorized-scan.yml`):手动触发,对授权目标跑
  ember-scan,SARIF 上传为产物并推送 GitHub Code Scanning。

### Changed
- `run.py` 增加 `--spec`,消除硬编码的个人 openapi 路径。
- `network`:弱加密判定抽成纯函数 `is_weak_cipher()`。

### Fixed
- `scanner._req` 连接级错误现在退避重试而非直接放弃。
- **`scanner.py` main() 汇总行 `KeyError: 'duration_seconds'`**:把顶层字段误当成
  stats 字段,导致 CLI 每次在收尾崩溃、`--sarif` 永不写出。加了 CLI 端到端回归测试堵住此口。
