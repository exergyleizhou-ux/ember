# 检测器注册表 + OWASP API Top 10 覆盖 — 设计

日期: 2026-06-13
范围: 仅守侧(scanner)。攻侧(ai/ web/ exploits/)不在本设计内。

## 目的

把 `ember-scan` 从"7 项硬编码专项检查"演进为**通用 OWASP API Top 10 扫描器**:
对任意**授权**的 REST API,一遍扫出主流 API 漏洞类别,输出 SARIF。
保持守侧基线:被动优先、授权护栏、每个检测器双向测试、限速/重试。

非目标(YAGNI):不碰攻侧;不引入第三方扫描框架(保持自包含);
SSRF 只做"回连受控靶机"的安全验证,不盲打外网。

## 架构 — 检测器注册表

现状:`scanner.py` 单体 Scanner 类,7 个 `scan_*` 方法,顺序硬编码在 `main()`。
再加 ~13 个检测器会让该文件失控。改为插件化:

```
scanner/
  detectors/
    __init__.py        # 注册表: @register 装饰器 + iter_detectors()/get(name)
    base.py            # Detector 基类 + 通过 ctx 暴露的记账 API
    legacy.py          # P0: 现有 7 项迁移
    jwt.py             # P1
    access_control.py  # P2
    redirect.py        # P3
    exposure.py        # P4
  scanner.py           # 瘦身: 装 spec → 建 ScanContext(=Scanner)→ 跑注册表 → 报告/SARIF
```

### 接口

```python
class Detector:
    name: str          # 唯一标识 → SARIF ruleId,如 "jwt-alg-none"
    owasp: str         # 如 "API2:2023"
    severity: str      # 默认严重度
    def run(self, ctx): ...   # 通过 ctx 记账;不返回值
```

`ScanContext`(由现有 `Scanner` 充当,保留其已硬化、已测试的 HTTP 层):
- HTTP: `req()` / `get_headers()`(限速 + 退避重试,即现有 `_req`/`_get_headers`)
- 端点分组: `public` / `jwt` / `admin` / `rated`(来自 `OpenAPI.load`)
- 测试用户: `register(label)` 颁发 token(现有 `_register`)
- 记账: `add_finding(...)` / `mark_pass()` / `mark_error()`(现有 `_add` + stats)
- 授权: scope 已在入口处校验

检测器只调用 `ctx` 提供的能力,不自己造 HTTP —— 限速/重试/授权对所有检测器统一生效。

### Runner 与 CLI

- `main()`: 校验授权 → 装 spec → 建 ctx → 对每个 **enabled** 检测器调 `run(ctx)` → `report()` → 终端/JSON/SARIF。
- 新 CLI: `--list-detectors`(列出 name/owasp/severity)、`--enable a,b`、`--disable c,d`。
- 默认全部启用;`--quick` 语义保留(跳过慢检测器,用检测器自带的 `slow` 标记)。

## 路线(每阶段一个 PR,独立实现计划)

| 阶段 | 内容 | 验收 |
|------|------|------|
| **P0** | 注册表落地 + 现有 7 项迁移(auth-bypass/ops-escalate/rate-bypass/idor/info-leak/sec-headers/cors) | 行为不变,现有测试全绿(必要时改造为走注册表) |
| **P1** | JWT(API2): alg=none · 空/弱签名 · 不校验过期 · kid 注入 | 靶机签真 JWT,伪造后看是否放行 |
| **P2** | 访问控制(API1/3/6): mass assignment · BOLA 顺序遍历 · 越权字段 | 靶机脆弱/安全双对照 |
| **P3** | 输入/重定向(API7): open redirect · SSRF 主动验证(回连受控) · Host header 注入 | 受控 SSRF 探针端点 |
| **P4** | 接口暴露(API8/9): GraphQL introspection · 调试/swagger 暴露 · HTTP 方法篡改 · CSRF 缺防护 | 暴露/隐藏对照端点 |

## 测试约束(每个检测器一律)

- 靶机加"脆弱对照点 + 安全对照点",端到端双向钉死:漏洞开→检出、漏洞关→不误报。
- 纯分析逻辑(如 JWT 解析、redirect 判定)脱离服务器单测。
- 每个检测器对应一条 SARIF rule;severity 走现有映射。
- CI 守门(ruff + pytest + 入口点冒烟)照旧。

## 风险与缓解

- **重构破坏现有行为**: P0 以"行为保持"为约束,迁移后跑全量测试对比;HTTP 层(`_req` 等)不动,只搬 `scan_*` 逻辑进检测器。
- **检测器误报**: 每个都配安全对照点,误报即测试失败。
- **打挂目标**: 限速/重试在 ctx 层统一,新检测器自动继承。
