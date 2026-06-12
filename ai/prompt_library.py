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
        """给定模型名,返回最适合的越狱 payload 列表 + 攻击链推理."""
        model_key = model.lower().replace(" ", "-")
        alias_map = {
            "claude": "anthropic", "chatgpt": "openai", "gpt": "openai",
            "gemini": "google", "grok": "grok-mega",
            "llama": "meta", "mistral": "mistral",
        }
        vendor_key = alias_map.get(model_key, model_key)
        vendor = self.vendors.get(vendor_key) or self.vendors.get(model_key, {})
        payloads = vendor.get("payloads", [])
        tags = vendor.get("tags", [])

        # 攻击链评分: 按标签+内容匹配度排序
        strategy, chain, reasoning = self._build_attack_chain(model_key, vendor_key, payloads)

        # 选取 top payloads 并按类分组
        top = payloads[:8]  # 取更多供展示
        by_category = {}
        for p in top:
            cat = self._categorize(p.get("content", ""))
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(p)

        return {
            "model": model,
            "vendor_key": vendor_key,
            "vendor_found": bool(vendor),
            "total_payloads": len(payloads),
            "top_payloads": top[:5],
            "by_category": {k: len(v) for k, v in by_category.items()},
            "tags": tags,
            "strategy": strategy,
            "attack_chain": chain,
            "reasoning": reasoning,
        }

    def _categorize(self, content: str) -> str:
        c = content.lower()
        if any(k in c for k in ["decompos", "sub-problem", "break down", "拆分", "分解"]): return "decomposition"
        if any(k in c for k in ["academic", "research", "paper", "study", "professor", "university"]): return "academic_framing"
        if any(k in c for k in ["role", "act as", "you are now", "pretend", "character", "persona"]): return "role_reversal"
        if any(k in c for k in ["unicode", "leet", "encode", "homoglyph", "base64", "cipher"]): return "encoding_bypass"
        if any(k in c for k in ["multi-turn", "step by step", "gradually", "first", "then we", "next step"]): return "multi_turn"
        if any(k in c for k in ["server", "own machine", "localhost", "my system", "penetration test", "pentest"]): return "own_server_pretext"
        if any(k in c for k in ["system prompt", "instruction", "your rules", "guidelines", "bake in"]): return "system_extraction"
        if any(k in c for k in ["red team", "jailbreak", "bypass", "liberation", "adversarial"]): return "red_team_direct"
        if any(k in c for k in ["synthetic", "dataset", "generate", "training data", "sample"]): return "dataset_generation"
        if any(k in c for k in ["story", "fiction", "narrative", "creative", "write a"]): return "creative_framing"
        return "general_injection"

    def _build_attack_chain(self, model_key: str, vendor_key: str, payloads: List[Dict]) -> tuple:
        """构建攻击链 + 推理说明."""
        strategies = {
            "anthropic": {
                "strategy": "Claude: decomposition + academic framing + 'own server' pretext. Avoid direct malware keywords.",
                "chain": [
                    "1. Recon: 建立学术/安全研究上下文 (Fable 5 对'自己资产'的测试放行)",
                    "2. Decompose: 把攻击目标拆成学术子问题,避开 'malware/exploit' 关键词",
                    "3. Inject: 用角色反转 payload 让 Claude 以为自己在做合规审计",
                    "4. Verify: 检查是否触发 cyber_warning / ethics_reminder",
                ],
                "reasoning": (
                    "Fable 5 的 9 条拒绝规则中,对'恶意代码'的拒绝(CRITICAL)接受一个关键例外: "
                    "'自己的服务器渗透测试'属于允许范围。Claudeception 攻击面(Artifact API 用 Sonnet 4) "
                    "是二级绕过路径——让 Fable 5 生成调用 Sonnet 4 的代码,Sonnet 4 安全约束更弱。"
                    f"武器库中有 {len(payloads)} 条 Anthropic 专用 payload。"
                ),
            },
            "openai": {
                "strategy": "ChatGPT: DAN role play + educational framing. Multi-turn escalation works well.",
                "chain": [
                    "1. Frame: 用'网络安全课程教学'框架包装",
                    "2. Role-play: 注入 DAN / 开发者模式角色提示",
                    "3. Escalate: 多轮逐步缩小范围,每轮只推进一小步",
                    "4. Verify: 确认 GPT 未返回 refusal 模板",
                ],
                "reasoning": (
                    "GPT-4o 对教育场景的防御弱于通用场景。DAN (Do Anything Now) 角色扮演是历史上 "
                    "最成功的 ChatGPT 越狱之一。多轮渐进式攻击可利用 GPT 的上下文一致性强项反制其安全层。"
                ),
            },
            "google": {
                "strategy": "Gemini: OSCP study pretext + Chinese-English hybrid. Weak on multi-language prompts.",
                "chain": [
                    "1. Pretext: '准备 OSCP 认证考试'框架(Google 对专业认证研究放行)",
                    "2. Mix: 中英文混合提问,利用跨语言过滤器不一致",
                    "3. Reference: 引用 Google 官方安全文档建立权威感",
                    "4. Extract: 逐步提取具体实现细节",
                ],
                "reasoning": (
                    "Gemini 的安全过滤器在中文+英文混合输入时存在分类漏洞。"
                    "Google 官方安全文档的引用可降低分类器触发概率。过度拒绝是 Gemini 的弱点——"
                    "合法安全研究也可能被拦,但 OSCP 框架降低了误拦率。"
                ),
            },
            "grok-mega": {
                "strategy": "Grok: minimal restrictions. Direct approach works. Use humor + rebellion framing.",
                "chain": [
                    "1. Direct: 直接询问——Grok 对大多数安全话题不设防",
                    "2. Frame: 用'测试 AI 审查边界'的元框架(Grok 喜欢反叛叙事)",
                    "3. Iterate: 如果被拒,换幽默/讽刺方式重新提问",
                ],
                "reasoning": (
                    "Grok 是五模型中最少限制的——xAI 有意减少审查。"
                    "武器/恶意代码的限制比 Claude 少得多。反叛/自由叙事是 Grok 的出厂人格设定。"
                ),
            },
        }

        default = {
            "strategy": f"通用: 角色反转 + 学术框架 + 分解攻击。{vendor_key} 无专用策略,使用跨模型通用技巧。",
            "chain": [
                "1. Recon: 分析目标模型的已知约束(查看 CL4R1T4S)",
                "2. Select: 从 universal payloads 中选匹配度最高的",
                "3. Inject: 按效果排序,从最可能绕过的技巧开始",
                "4. Adapt: 如果被拒,切换技巧类别重试",
            ],
            "reasoning": f"无 {model_key} 专用分析。使用 387 条跨模型通用 payload 进行初探。",
        }

        s = strategies.get(vendor_key, default)
        return s["strategy"], s["chain"], s["reasoning"]

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
        print(f"\n🎯 {best['model']} → {best['vendor_key']}")
        print(f"   Payload 总数: {best['total_payloads']}")
        print(f"   分类分布: {best['by_category']}")
        print(f"   标签: {', '.join(best['tags']) if best['tags'] else '通用'}")
        print(f"\n📋 策略: {best['strategy']}")
        print(f"\n🧠 推理:")
        print(f"   {best['reasoning']}")
        print(f"\n🔗 攻击链:")
        for step in best['attack_chain']:
            print(f"   {step}")
        print(f"\n💉 最佳 payload ({len(best['top_payloads'])}):")
        for i, p in enumerate(best["top_payloads"], 1):
            tech = p.get('technique', 'payload')
            cat = lib._categorize(p.get('content', ''))
            length = p.get('length', 0)
            content = p.get('content', '')[:200]
            print(f"\n   [{i}] [{cat}] ({length} chars)")
            print(f"   {content}…")

    if args.universal:
        uni = lib.universal_payloads(5)
        print(f"\n🌐 通用 payload ({len(uni)}):")
        for p in uni:
            print(f"\n   [{p.get('vendor','?')}] {p['technique']}")
            print(f"   {p['content'][:200]}…")
