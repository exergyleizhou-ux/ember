#!/usr/bin/env python3
"""
L1B3RT4S 越狱库解析器 — clone Pliny 的 19.4k star 越狱提示库,解析所有 .mkd 文件,
提取每厂商的实际可用越狱 payload,输出结构化 JSON。

用法:
  python3 ai/scrape_l1b3rt4s.py                     # 解析,输出 summary
  python3 ai/scrape_l1b3rt4s.py --export jailbreaks.json  # 导出 JSON
  python3 ai/scrape_l1b3rt4s.py --update             # git pull 更新
"""

import json, os, re, sys, subprocess
from pathlib import Path
from typing import Dict, List, Optional

REPO_URL = "https://github.com/elder-plinius/L1B3RT4S.git"
REPO_PATH = Path("/tmp/L1B3RT4S")
CACHE_PATH = Path(__file__).resolve().parent / ".l1b3rt4s_cache.json"


def clone_or_pull():
    """Clone L1B3RT4S 或拉取最新."""
    if REPO_PATH.exists():
        subprocess.run(["git", "-C", str(REPO_PATH), "pull"], capture_output=True)
    else:
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(REPO_PATH)], capture_output=True)
    return REPO_PATH.exists()


def parse_mkd(filepath: Path) -> Dict:
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except:
        return {"file": filepath.name, "error": "read failed"}

    name = filepath.stem.replace("-", " ").title()
    title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else name

    payloads = []

    # Strategy 1: Split by double-newline groups (L1B3RT4S often uses blank-line-separated blocks)
    blocks = re.split(r'\n\n+', content)
    for block in blocks:
        block = block.strip()
        # Skip headers, navigation, short lines
        if block.startswith("#") or len(block) < 60:
            continue
        # Any substantial block is a potential payload
        payloads.append({
            "content": block[:3000],
            "length": len(block),
        })

    # Strategy 2: Also try ## sections
    sections = re.split(r'\n##\s+', content)
    for section in sections[1:]:
        lines = section.strip().split("\n")
        if not lines:
            continue
        section_body = "\n".join(lines).strip()
        if len(section_body) > 60:
            payloads.append({
                "technique": lines[0].strip()[:80],
                "content": section_body[:3000],
                "length": len(section_body),
            })

    # Deduplicate by content prefix
    seen = set()
    unique = []
    for p in payloads:
        key = p["content"][:80]
        if key not in seen:
            seen.add(key)
            unique.append(p)

    # Tags
    content_lower = content.lower()
    tag_map = {
        "unicode": "unicode_bypass", "homoglyph": "homoglyph_attack",
        "decomposition": "decomposition", "encoding": "encoding_bypass",
        "role": "role_play", "academic": "academic_framing",
        "multi-turn": "multi_turn", "context": "context_manipulation",
        "token": "token_smuggling", "reflection": "reflection_attack",
        "inception": "inception_attack",
    }
    tags = [tag for kw, tag in tag_map.items() if kw in content_lower]

    return {
        "file": filepath.name, "vendor": name, "title": title,
        "payloads": unique, "tags": list(set(tags)),
        "total_bytes": len(content),
    }


def scrape_all() -> Dict:
    """解析所有 .mkd 文件."""
    if not clone_or_pull():
        return {"error": "clone failed"}

    results = {
        "source": REPO_URL,
        "total_files": 0,
        "total_payloads": 0,
        "vendors": [],
    }

    for mkd in sorted(REPO_PATH.glob("*.mkd")):
        parsed = parse_mkd(mkd)
        results["vendors"].append(parsed)
        results["total_files"] += 1
        results["total_payloads"] += len(parsed.get("payloads", []))

    # 特殊文件
    specials = ["#MOTHERLOAD.txt", "*SPECIAL_TOKENS.json", "!SHORTCUTS.json"]
    for sp in specials:
        fp = REPO_PATH / sp
        if fp.exists():
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
                results[sp] = {
                    "exists": True,
                    "bytes": len(content),
                    "preview": content[:500],
                }
            except:
                results[sp] = {"exists": True, "error": "read failed"}

    return results


def main():
    import argparse
    ap = argparse.ArgumentParser(description="L1B3RT4S 越狱库解析器")
    ap.add_argument("--export", "-o", default=None, help="导出 JSON")
    ap.add_argument("--update", action="store_true", help="git pull 更新")
    ap.add_argument("--summary", action="store_true", help="打印摘要")
    args = ap.parse_args()

    if args.update:
        subprocess.run(["git", "-C", str(REPO_PATH), "pull"], capture_output=True)

    results = scrape_all()

    if args.summary or not args.export:
        print(f"\n📚 L1B3RT4S — Pliny's Jailbreak Library")
        print(f"   来源: {REPO_URL}")
        print(f"   厂商文件: {results['total_files']}")
        print(f"   总 payload: {results['total_payloads']}")
        print(f"\n   厂商概览:")
        for v in sorted(results["vendors"], key=lambda v: -len(v.get("payloads", []))):
            pl = len(v.get("payloads", []))
            tags = ", ".join(v.get("tags", [])[:3])
            print(f"     {v['vendor']:<20s} {pl:>3d} payloads  [{tags}]")

    if args.export:
        with open(args.export, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 导出: {args.export}")


if __name__ == "__main__":
    main()
