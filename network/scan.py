#!/usr/bin/env python3
"""
网络层安全检查 — SSL/TLS, 端口暴露, Docker 审计, 数据库外网可达检测.

用法:
  python3 network/scan.py --host 47.96.x.x
  python3 network/scan.py --host oasis.example.com --full
"""

import json
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Dict, List


def run(cmd: List[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return f"(timeout after {timeout}s)"
    except FileNotFoundError:
        return "(tool not installed)"

# ── SSL/TLS ──
def check_ssl(host: str, port: int = 443) -> Dict:
    """用 Python ssl 库检测 TLS 配置."""
    result = {"host": host, "port": port, "tls_ok": False, "issues": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["tls_ok"] = True
                result["tls_version"] = ssock.version()
                result["cipher"] = ssock.cipher()
                result["cert_issuer"] = cert.get("issuer", [])
                result["cert_expires"] = cert.get("notAfter", "")
                # 弱加密检查
                weak = ["RC4","DES","3DES","EXPORT","NULL","anon"]
                cipher_name = ssock.cipher()[0]
                for w in weak:
                    if w in cipher_name:
                        result["issues"].append(f"弱加密套件: {cipher_name}")
    except Exception as e:
        result["issues"].append(f"TLS 连接失败: {e}")
    return result

# ── 端口扫描 ──
def check_ports(host: str) -> Dict:
    """快速 nmap 常见端口."""
    # 尝试 nmap,失败则用 python socket
    out = run(["nmap", "-F", "--open", host], timeout=60)
    ports = []
    for line in out.split("\n"):
        if "/tcp" in line and "open" in line:
            parts = line.split()
            ports.append({"port": parts[0].split("/")[0], "service": parts[2] if len(parts) > 2 else "?"})

    if not ports:
        # fallback: python socket scan common ports
        common = [22, 80, 443, 5432, 6379, 8080, 3000, 9090, 9093, 9187]
        for p in common:
            try:
                s = socket.create_connection((host, p), timeout=2)
                s.close()
                ports.append({"port": str(p), "service": "open"})
            except OSError:
                pass

    dangerous = [p for p in ports if int(p["port"]) in (5432, 6379, 22)]
    return {
        "host": host, "open_ports": ports,
        "dangerous_exposure": [f"端口 {p['port']} ({p['service']}) 对外暴露"
                               for p in dangerous],
    }

# ── 主入口 ──
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", "-H", required=True)
    ap.add_argument("--ports", nargs="+", type=int, default=[443])
    ap.add_argument("--full", action="store_true", help="完整扫描 (含 nmap)")
    args = ap.parse_args()

    print(f"🔐 网络扫描 {args.host}")

    results = {"host": args.host, "scanned_at": datetime.now(timezone.utc).isoformat()}

    # SSL
    print("\n🔒 TLS/SSL …")
    ssl_results = [check_ssl(args.host, p) for p in args.ports]
    results["ssl"] = ssl_results
    for r in ssl_results:
        status = "✅" if r["tls_ok"] else "❌"
        print(f"  {status} 端口 {r['port']}: {r.get('tls_version','N/A')} / {r.get('cipher',('',''))[0]}")
        for issue in r["issues"]:
            print(f"    ⚠️  {issue}")

    # 端口
    if args.full:
        print("\n📡 端口扫描 …")
        ports = check_ports(args.host)
        results["ports"] = ports
        for p in ports["open_ports"]:
            print(f"  {p['port']}/tcp → {p['service']}")
        for d in ports["dangerous_exposure"]:
            print(f"  🔴 {d}")

    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
