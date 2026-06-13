# Changelog

本项目的显著变更记录于此。版本遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased] — 守侧生产化

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

### Changed
- `run.py` 增加 `--spec`,消除硬编码的个人 openapi 路径。
- `network`:弱加密判定抽成纯函数 `is_weak_cipher()`。

### Fixed
- `scanner._req` 连接级错误现在退避重试而非直接放弃。
