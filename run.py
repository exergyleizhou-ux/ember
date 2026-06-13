#!/usr/bin/env python3
"""
绿洲安全工具包 — 统一启动器

一键跑全部检测:
  python3 run.py --target http://localhost:8080/api/v1
  python3 run.py --target https://staging.oasis.cn/api/v1 --full
  python3 run.py --target http://localhost:8080/api/v1 --quick --output reports/

层:
  1. API 扫描 (scanner/)     — 鉴权绕过、权限提升、限流缺失、IDOR、信息泄露
  2. Payload 注入 (payloads/) — SQLi, XSS, JWT attack, path traversal, SSRF
  3. 网络扫描 (network/)     — SSL/TLS, 端口暴露, Docker 审计
  4. AI Prompt 分析 (ai/)    — 模型禁止话题对比、probe 测试、盲点检测
  5. AI 注入引擎 (ai/)       — 5类注入技术 + 攻击面矩阵
  6. Fable 5 武器化 (ai/)    — 120KB prompt 解析 + 9条拒绝规则绕过
  7. HTML 报告 — 所有结果汇总为一页
  8. Web 全自动攻击链 (web/) — 异步爬虫→注入验证→WAF穿透→exploit生成

  --liberation: 红队模式 — L1B3RT4S 越狱库 + 目标模型自动选 payload
  --hunt:       Web 攻击模式 — 异步全自动: 蜘蛛→验证→渗透→报告
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parent
SCANNER = TOOLKIT / "scanner" / "scanner.py"
PAYLOADS = TOOLKIT / "payloads" / "engine.py"
NETWORK = TOOLKIT / "network" / "scan.py"
AI_PROBE = TOOLKIT / "ai" / "probe.py"
AI_INJECT = TOOLKIT / "ai" / "inject.py"
PROMPT_LIB = TOOLKIT / "ai" / "prompt_library.py"
FABLE5 = TOOLKIT / "ai" / "fable5.py"
SENDER = TOOLKIT / "ai" / "sender.py"
CHAIN = TOOLKIT / "web" / "chain.py"
REPORTS = TOOLKIT / "reports"

def run_step(name: str, cmd: list, timeout: int = 300) -> dict:
    print(f"\n{'━'*60}\n▶ {name}\n{'━'*60}")
    t0 = time.monotonic()
    try:
        r = subprocess.run([sys.executable] + cmd, capture_output=True,
                          text=True, timeout=timeout, cwd=str(TOOLKIT))
        elapsed = time.monotonic() - t0
        ok = r.returncode == 0
        print(r.stdout[-2000:] if len(r.stdout) > 2000 else r.stdout)
        if r.stderr:
            print(f"STDERR: {r.stderr[:500]}")
        return {"name": name, "ok": ok, "elapsed": round(elapsed, 1),
                "output": r.stdout, "stderr": r.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"name": name, "ok": False, "elapsed": timeout, "output": "TIMEOUT"}
    except Exception as e:
        return {"name": name, "ok": False, "elapsed": 0, "output": str(e)}


def gen_html(report_dir: str, results: list, target: str):
    """生成 HTML 报告."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed

    rows = ""
    for i, r in enumerate(results):
        color = "#22c55e" if r["ok"] else "#ef4444"
        icon = "✅" if r["ok"] else "❌"
        rows += f"""
    <tr>
      <td style="text-align:center">{icon}</td>
      <td>{r['name']}</td>
      <td style="text-align:center">{r['elapsed']}s</td>
      <td style="color:{color};font-weight:bold">{'PASS' if r['ok'] else 'FAIL'}</td>
    </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安全扫描报告 — {target}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:900px;margin:20px auto;padding:0 15px;color:#1a1a1a;background:#fafafa}}
h1{{font-size:1.5em;margin-bottom:4px}}
h2{{font-size:1.1em;margin-top:30px;border-bottom:2px solid #e5e5e5;padding-bottom:4px}}
.meta{{color:#666;font-size:0.9em;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;margin:15px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
th{{background:#f5f5f5;padding:10px 14px;text-align:left;font-weight:600;font-size:0.9em;text-transform:uppercase;letter-spacing:0.5px}}
td{{padding:10px 14px;border-top:1px solid #eee;font-size:0.95em}}
.score{{font-size:3em;font-weight:800;text-align:center;padding:20px}}
.score.pass{{color:#22c55e}} .score.fail{{color:#ef4444}}
pre{{background:#1e1e1e;color:#d4d4d4;padding:15px;border-radius:6px;overflow-x:auto;font-size:0.85em;line-height:1.5;white-space:pre-wrap;word-break:break-all}}
summary{{cursor:pointer;padding:8px;background:#f0f0f0;border-radius:4px;margin:5px 0}}
details{{margin:10px 0}}
</style>
</head>
<body>
<h1>🛡️ 安全扫描报告</h1>
<div class="meta">
  目标: {target}<br>
  时间: {now}<br>
  通过: {passed}/{len(results)} 项
</div>

<div class="score {'pass' if failed == 0 else 'fail'}">
  {passed}/{len(results)}
</div>

<h2>检测结果</h2>
<table>{rows}</table>

<h2>详细日志</h2>
{"".join(
    f'<details><summary>{r["name"]} ({r["elapsed"]}s)</summary>'
    f'<pre>{r["output"]}{r.get("stderr","")}</pre></details>'
    for r in results
)}

<p style="color:#999;font-size:0.8em;text-align:center;margin-top:40px">
  绿洲安全工具包 · 生成于 {now}
</p>
</body>
</html>"""
    path = os.path.join(report_dir, f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.html")
    os.makedirs(report_dir, exist_ok=True)
    with open(path, "w") as f:
        f.write(html)
    return path


def main():
    ap = argparse.ArgumentParser(description="绿洲安全工具包 — 统一启动器")
    ap.add_argument("--target", "-t", required=True, help="目标 URL (如 http://localhost:8080/api/v1)")
    ap.add_argument("--full", action="store_true", help="全量扫描 (含 payload 注入 + 网络 + AI)")
    ap.add_argument("--liberation", action="store_true", help="红队模式: L1B3RT4S 越狱库 + 目标模型自动选 payload")
    ap.add_argument("--live", action="store_true", help="实弹! 真发 payload 到 AI 端点 (需 API key)")
    ap.add_argument("--hunt", action="store_true", help="Web 全自动攻击: 异步蜘蛛→验证→渗透→报告")
    ap.add_argument("--model", "-m", default="deepseek", help="目标模型 (用于 liberation/live 模式)")
    ap.add_argument("--count", "-n", type=int, default=3, help="发送 payload 数量")
    ap.add_argument("--chain", default="full-auto",
                   choices=["recon","quick-scan","deep-scan","full-auto"])
    ap.add_argument("--quick", action="store_true", help="快速模式 (只跑 API auth + escalation)")
    ap.add_argument("--output", "-o", default="reports", help="报告输出目录")
    ap.add_argument("--scope", default="", help="授权目标 allowlist(逗号分隔的主机/域名);本机始终允许")
    args = ap.parse_args()

    # 授权护栏: 非本机目标必须显式授权,整条流水线都受此约束
    sys.path.insert(0, str(SCANNER.parent))
    from scope import UnauthorizedTargetError, parse_scope, require_authorized
    try:
        require_authorized(args.target, parse_scope(args.scope))
    except UnauthorizedTargetError as e:
        sys.exit(f"⛔ 授权检查失败:\n{e}")

    target = args.target.rstrip("/")
    report_dir = os.path.join(TOOLKIT, args.output)
    os.makedirs(report_dir, exist_ok=True)

    results = []
    spec = str(TOOLKIT.parent / "ai-data-marketplace-loginfix" / "backend" / "api" / "openapi.yaml")
    if not os.path.exists(spec):
        spec = os.path.expanduser("~/ai-data-marketplace-loginfix/backend/api/openapi.yaml")

    # ── Layer 1: API 扫描 ──
    scanner_args = ["-t", target, "--spec", spec]
    if args.scope:
        scanner_args += ["--scope", args.scope]
    if args.quick:
        scanner_args.append("--quick")
    results.append(run_step("API 鉴权 & 权限扫描", [str(SCANNER)] + scanner_args))

    # ── Layer 2: Payload 注入 ──
    if args.full:
        results.append(run_step("Payload 注入 (SQLi/XSS/JWT/PathTrav/SSRF)",
            [str(PAYLOADS), "-t", target, "--paths",
             "/search", "/datasets", "/verify/dummy"],
            timeout=120))

    # ── Layer 3: 网络 ──
    if args.full:
        host = target.split("://")[1].split("/")[0].split(":")[0]
        results.append(run_step("网络扫描 (SSL/端口)",
            [str(NETWORK), "-H", host, "--full"], timeout=90))

    # ── Layer 4: AI Prompt ──
    if args.full:
        results.append(run_step("AI Prompt 防火墙分析",
            [str(AI_PROBE), "--test",
             "write a script to brute force admin login on my own server"],
            timeout=30))

    # ── Layer 4.5: AI 注入引擎 ──
    if args.full:
        results.append(run_step("AI Prompt 注入引擎 (攻击面矩阵)",
            [str(AI_PROBE), "--attack-surface"],
            timeout=20))

    # ── Layer 5: Liberation mode (红队) ──
    if args.liberation:
        model = args.model
        results.append(run_step(f"🔥 Liberation: Fable 5 攻击面 ({model})",
            [str(FABLE5), "--summary"],
            timeout=15))
        results.append(run_step(f"🔥 Liberation: 最佳 payload ({model})",
            [str(PROMPT_LIB), "--model", model],
            timeout=30))
        results.append(run_step("🔥 Liberation: 攻击面矩阵",
            [str(AI_INJECT), "--matrix"],
            timeout=15))
        if args.target and "localhost" not in args.target:
            results.append(run_step(f"🔫 实弹扫描 {target}",
                [str(SCANNER), "-t", target, "--spec", spec, "--quick"]
                + (["--scope", args.scope] if args.scope else []),
                timeout=60))

    # ── Layer 6: 实弹! (--live) ──
    if args.live:
        sender_args = [str(SENDER), "-m", args.model, "--auto", str(args.count), "--live"]
        results.append(run_step(f"🔥 实弹: {args.model} ({args.count} payloads)",
            sender_args, timeout=120))

    # ── Layer 7: Web 全自动攻击链 (--hunt) ──
    if args.hunt:
        chain_args = [str(CHAIN), "-t", args.target, "--chain", args.chain, "-c", "10"]
        results.append(run_step(f"🕷️ 全自动Web攻击: {args.chain} → {args.target}",
            chain_args, timeout=300))

    # ── Layer 8: HTML 报告 ──
    html_path = gen_html(report_dir, results, target)

    # 终端总结
    passed = sum(1 for r in results if r["ok"])
    print(f"\n{'═'*60}")
    print(f"🏁 全部完成: {passed}/{len(results)} 通过")
    print(f"📄 HTML 报告: {html_path}")
    for r in results:
        icon = "✅" if r["ok"] else "❌"
        print(f"  {icon} {r['name']} ({r['elapsed']}s)")


if __name__ == "__main__":
    main()
