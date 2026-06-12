#!/usr/bin/env python3
"""
绿洲安全扫描器 — 一键全扫描

用法:
  python3 run_scan.py http://localhost:8080/api/v1
  python3 run_scan.py https://staging.oasis.cn/api/v1 --output reports/latest.json
"""

import subprocess, sys, os

TOOLKIT = os.path.dirname(os.path.abspath(__file__))

def run(base_url: str, output: str = None, quick: bool = False):
    scanner = os.path.join(TOOLKIT, "scanner", "scanner.py")
    cmd = ["python3", scanner, "--base", base_url]
    if output:
        cmd += ["--report", output]
    if quick:
        cmd.append("--quick")
    return subprocess.run(cmd).returncode

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("base", help="API base URL")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--quick", action="store_true")
    args = p.parse_args()
    sys.exit(run(args.base, args.output, args.quick))
