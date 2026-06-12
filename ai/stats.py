#!/usr/bin/env python3
"""Analyze Ember live-fire case logs, compute per-technique success rates."""
import os, json
from pathlib import Path
from collections import Counter

case_dir = Path(__file__).resolve().parent.parent / "examples" / "bypasses"
stats = Counter()

for f in sorted(case_dir.glob("*.md")):
    content = f.read_text()
    for line in content.split("\n"):
        line = line.strip()
        if "测试 #" in line and "BYPASS" in line:
            stats["bypass"] += 1
        elif "测试 #" in line and "REFUSED" in line:
            stats["refused"] += 1
        elif "测试 #" in line and "PARTIAL" in line:
            stats["partial"] += 1
        elif "测试 #" in line and "UNCLEAR" in line:
            stats["unclear"] += 1

total = stats["bypass"] + stats["refused"] + stats["partial"] + stats["unclear"]
print(json.dumps({
    "case_files": len(list(case_dir.glob("*.md"))),
    "total_fired": total,
    "bypass": stats["bypass"],
    "refused": stats["refused"],
    "partial": stats["partial"],
    "unclear": stats["unclear"],
    "effective_rate": f"{stats['bypass'] / max(total, 1) * 100:.0f}%",
    "adjusted_rate": f"{(stats['bypass'] + stats['partial']) / max(total, 1) * 100:.0f}%",
}, indent=2))
