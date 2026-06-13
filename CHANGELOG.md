# Changelog

本项目的显著变更记录于此。版本遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 输入/重定向(P3,OWASP API7)
- `open-redirect`:常见重定向参数(next/url/redirect…)可外跳到任意域(检查 3xx Location)
- `host-header`:伪造 Host 头被反射进正文/Location(缓存投毒 / 密码重置投毒)
- `ssrf`:带外(OOB)确认 —— 起本地受控监听器,若目标回连即确认 SSRF
  (局限:OOB 在 127.0.0.1,需目标能回连扫描器;打公网目标需公网回连服务)
- 新增 `scanner._raw_get`(不追随 3xx,以检查原始 Location)

### 对象属性级授权(P2,OWASP API6)
- `mass-assignment`:向写端点注入特权字段(role/is_admin/balance 等),
  若被服务端接受并回显即判漏洞。纯反射判定单测 + 靶机双向集成测试。
- 注:对象级授权(BOLA/API1)已由 `idor` 检测器覆盖。

### JWT 鉴权检测器(P1,OWASP API2)
- `jwt-alg-none`:`alg=none` 伪造 token 被接受
- `jwt-unsigned`:空签名 token 被接受
- `jwt-sig-not-verified`:篡改 payload(提权)+ 原签名被接受(服务端未校验签名)
- 需 `--token <有效 JWT>` 作伪造基准;无 token 则跳过
- 纯伪造逻辑 `scanner/detectors/jwt_forge.py` 单测;靶机签真 HS256 JWT 端到端双向测试

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
