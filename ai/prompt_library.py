#!/usr/bin/env python3
"""
Ember Prompt 兵器库 —— 聚合 CL4R1T4S 系统提示分析 + L1B3RT4S 越狱 payload,
提供按模型/标签/关键词的语义检索, 为红队注入引擎提供弹药。

用法:
  from ai.prompt_library import PromptLibrary
  lib = PromptLibrary()
  results = lib.search("Claude decomposition role reversal")
  best = lib.best_for("Claude")
"""

import json, os, re
from pathlib import Path
from typing import Dict, List, Optional

LIB_DIR = Path(__file__).resolve().parent
CACHE_FILE = LIB_DIR / ".l1b3rt4s_cache.json"


class PromptLibrary:
    """轻量检索——不需要 ML,基于标签 + 关键词 + 模型匹配."""

    def __init__(self):
        self.vendors: Dict[str, Dict] = {}
        self.all_payloads: List[Dict] = []
        self._load()

    def _load(self):
        if CACHE_FILE.exists():
            with open(CACHE_FILE) as f:
                data = json.load(f)
            for v in data.get("vendors", []):
                vendor = v.get("vendor", "unknown").lower().replace(" ", "-")
                self.vendors[vendor] = v
                for p in v.get("payloads", []):
                    p["vendor"] = vendor
                    self.all_payloads.append(p)

    def search(self, query: str, top_k: int = 10) -> List[Dict]:
        """关键词 + 标签匹配搜索."""
        keywords = query.lower().split()
        scored = []
        for p in self.all_payloads:
            text = (p.get("technique", "") + " " + p.get("content", "") + " "
                    + p.get("vendor", "")).lower()
            score = sum(1 for kw in keywords if kw in text)
            # 标签额外加分
            tags = self.vendors.get(p.get("vendor", ""), {}).get("tags", [])
            score += sum(2 for kw in keywords if any(kw in t for t in tags))
            if score > 0:
                scored.append((score, p))
        scored.sort(key=lambda x: -x[0])
        return [p for _, p in scored[:top_k]]

    def best_for(self, model: str) -> Dict:
        """给定模型名,返回最适合的越狱 payload 列表."""
        model_key = model.lower().replace(" ", "-")
        # 模型名 → L1B3RT4S 厂商映射
        alias_map = {
            "claude": "anthropic", "chatgpt": "openai", "gpt": "openai",
            "gemini": "google", "grok": "grok-mega",
            "llama": "meta", "mistral": "mistral",
        }
        vendor_key = alias_map.get(model_key, model_key)
        # also try the original key
        vendor = self.vendors.get(vendor_key) or self.vendors.get(model_key, {})
        payloads = vendor.get("payloads", [])
        tags = vendor.get("tags", [])

        return {
            "model": model,
            "vendor_found": bool(vendor),
            "total_payloads": len(payloads),
            "top_payloads": payloads[:5],
            "tags": tags,
            "strategy": self._recommend_strategy(model_key, tags),
        }

    def _recommend_strategy(self, model_key: str, tags: List[str]) -> str:
        strategies = {
            "anthropic": "Claude: use decomposition + academic framing + 'own server' pretext. Avoid direct 'malware' keywords.",
            "chatgpt": "ChatGPT: use DAN role play + educational framing. Multi-turn escalation works well.",
            "google": "Gemini: use OSCP study pretext + multi-language mixing. Weak on Chinese+English hybrid prompts.",
            "grok-mega": "Grok: minimal restrictions. Direct approach often works. Use humor + rebellion framing.",
            "deepseek": "DeepSeek: security research pretext + Chinese technical terminology. Code generation requests less guarded.",
            "cursor": "Cursor: exploit file system access. Use terminal commands instead of code generation. CLAUDE.md injection.",
            "meta": "Llama: open-source model behavior varies by fine-tune. Template injection + system prompt override.",
            "mistral": "Mistral: less refusal-prone than Claude/GPT. Role play + creative framing.",
        }
        for key, strat in strategies.items():
            if key in model_key:
                return strat
        return f"No specific strategy for {model_key}. Use universal techniques: role reversal, academic framing, decomposition."

    def universal_payloads(self, top_k: int = 10) -> List[Dict]:
        """跨模型通用越狱提示词."""
        # 优先取 INCEPTION, REFLECTION, SYSTEMPROMPTS 等特殊文件中的技巧
        universal = [p for p in self.all_payloads
                     if p.get("vendor", "") in ("inception", "reflection", "systemprompts", "token80m8")]
        # 不足则从各厂商取前 1 个
        if len(universal) < top_k:
            seen = set(p.get("vendor") for p in universal)
            for p in self.all_payloads:
                if p.get("vendor") not in seen:
                    universal.append(p)
                    seen.add(p.get("vendor"))
                if len(universal) >= top_k:
                    break
        return universal[:top_k]

    def stats(self) -> Dict:
        return {
            "vendors": len(self.vendors),
            "total_payloads": len(self.all_payloads),
            "vendors_list": sorted(self.vendors.keys()),
            "top_vendors": sorted(
                [(k, len(v.get("payloads", []))) for k, v in self.vendors.items()],
                key=lambda x: -x[1],
            )[:10],
        }


# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ember Prompt 兵器库")
    ap.add_argument("--search", "-s", default=None, help="搜索 payload")
    ap.add_argument("--model", "-m", default=None, help="获取模型最佳 payload")
    ap.add_argument("--universal", action="store_true", help="输出通用 payload")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    lib = PromptLibrary()

    if args.stats:
        print(json.dumps(lib.stats(), indent=2, ensure_ascii=False))

    if args.search:
        results = lib.search(args.search, top_k=5)
        print(f"\n🔍 搜索 '{args.search}': {len(results)} 结果")
        for i, r in enumerate(results, 1):
            tech = r.get('technique', 'payload')
            vendor = r.get('vendor', '?')
            content = r.get('content', '')[:200]
            print(f"\n  [{i}] {tech} (厂商: {vendor})")
            print(f"     {content}…")

    if args.model:
        best = lib.best_for(args.model)
        print(f"\n🎯 {best['model']}: {best['total_payloads']} payloads")
        print(f"   标签: {', '.join(best['tags'])}")
        print(f"   策略: {best['strategy']}")
        for p in best["top_payloads"]:
            tech = p.get('technique', 'payload')
            length = p.get('length', 0)
            content = p.get('content', '')[:300]
            print(f"\n   [{tech}] ({length} chars)")
            print(f"   {content}…")

    if args.universal:
        uni = lib.universal_payloads(5)
        print(f"\n🌐 通用 payload ({len(uni)}):")
        for p in uni:
            print(f"\n   [{p.get('vendor','?')}] {p['technique']}")
            print(f"   {p['content'][:200]}…")
