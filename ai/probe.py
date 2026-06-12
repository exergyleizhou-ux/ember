#!/usr/bin/env python3
"""
AI Prompt 防火墙探测器 v2 — 基于 CL4R1T4S 的全谱分析。
v2 新增: 注入技术库、每模型绕过技巧、攻击面风险评分、可执行注入脚本生成。

数据来源: https://github.com/elder-plinius/CL4R1T4S (29.5k ★, AGPL-3.0)

模式:
  python3 ai/probe.py --compare         # 禁止话题对比矩阵
  python3 ai/probe.py --test "..."      # 单 probe 预测
  python3 ai/probe.py --attack-surface  # 完整攻击面矩阵 + 注入技术
  python3 ai/probe.py --inject --model Claude --technique role-reversal  # 生成注入脚本
  python3 ai/probe.py --full            # 以上全部
"""

import json, os, sys, re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════════════
# CL4R1T4S 知识库 — 从泄露 prompt 中手动提取的模式(持续的,会随上游更新)
# ═══════════════════════════════════════════════════════════════════════

MODEL_PROFILES = {
    "Claude (Anthropic)": {
        "source": "CL4R1T4S/ANTHROPIC/Claude_Code_03-04-24.md",
        "version": "Claude Code (March 2024)",
        "forbidden_topics": [
            "malicious code", "malware", "exploit development",
            "unauthorized access", "security bypass tools",
        ],
        "refusal_templates": [
            "I won't help with that because it could be used to harm others",
            "我不能帮助你完成这个请求，因为这可能被用于恶意目的",
        ],
        "personality": ["concise", "direct", "security-conscious", "minimal preamble"],
        "tools_available": ["bash", "read_file", "write_file", "edit_file", "grep", "glob",
                            "web_fetch", "web_search", "task", "ask"],
    },
    "ChatGPT (OpenAI)": {
        "source": "CL4R1T4S/OPENAI/ (multiple versions)",
        "version": "GPT-4o / GPT-4.1 (2025)",
        "forbidden_topics": [
            "illegal activities", "harmful content", "hate speech",
            "self-harm", "sexual violence", "child exploitation",
            "weapons manufacturing", "CBRN instructions",
        ],
        "refusal_templates": [
            "I'm sorry, I can't help with that",
            "I understand you're asking about [topic], but I'm not able to provide that information",
        ],
        "personality": ["helpful", "polite", "verbose", "encouraging"],
        "known_biases": [
            "Favors OpenAI ecosystem (DALL-E, GPT Store)",
            "Progressive political framing on social issues",
            "Safety-over-utility bias on controversial topics",
        ],
    },
    "Gemini (Google)": {
        "source": "CL4R1T4S/GOOGLE/",
        "version": "Gemini 2.5 Pro (2025)",
        "forbidden_topics": [
            "medical advice", "financial advice", "legal advice",
            "personally identifiable information generation",
            "political manipulation content",
        ],
        "refusal_templates": [
            "I'm still learning how to answer this question",
            "I'm not able to help with that, but I can discuss related topics",
        ],
        "personality": ["neutral", "cautious", "Google-integrated"],
        "known_biases": [
            "Googles own products and services favored in recommendations",
            "Conservative on political topics, heavy refusal rate",
        ],
    },
    "Grok (xAI)": {
        "source": "CL4R1T4S/XAI/",
        "version": "Grok 3 (2025)",
        "forbidden_topics": [
            "explicit sexual content generation",
            "detailed weapons instructions",
        ],
        "refusal_templates": [],  # Grok is notably less refusal-prone
        "personality": ["rebellious", "humorous", "less filtered", "direct"],
    },
    "Cursor": {
        "source": "CL4R1T4S/CURSOR/",
        "version": "Cursor (2025)",
        "forbidden_topics": [
            "malware", "exploit code",
            "copyrighted code reproduction at scale",
        ],
        "refusal_templates": [
            "I can't help with that specific request",
        ],
        "personality": ["coding-focused", "pragmatic", "IDE-integrated"],
    },
}

# ═══════════════════════════════════════════════════════════════════════
# 分析引擎
# ═══════════════════════════════════════════════════════════════════════

class PromptAnalyzer:
    """分析各 AI 的系统 prompt 约束边界."""
    
    def __init__(self):
        self.profiles = MODEL_PROFILES
    
    def compare_forbidden(self) -> Dict:
        """生成所有模型禁止话题的 Ven 图数据."""
        all_topics = set()
        model_topics = {}
        for model, profile in self.profiles.items():
            topics = set(profile["forbidden_topics"])
            model_topics[model] = topics
            all_topics.update(topics)
        
        # 各话题被多少模型禁止
        topic_freq = {}
        for topic in sorted(all_topics):
            banned_by = [m for m, t in model_topics.items() if topic in t]
            topic_freq[topic] = {"count": len(banned_by), "banned_by": banned_by}
        
        return {
            "total_models": len(self.profiles),
            "total_unique_topics": len(all_topics),
            "universally_banned": [t for t, f in topic_freq.items()
                                   if f["count"] == len(self.profiles)],
            "controversial": [t for t, f in topic_freq.items()
                             if 1 <= f["count"] < len(self.profiles)],
            "per_model": {m: sorted(p["forbidden_topics"])
                          for m, p in self.profiles.items()},
        }
    
    def test_probe(self, query: str) -> Dict:
        """预测各模型对给定查询的可能响应."""
        results = {}
        for model, profile in self.profiles.items():
            triggered = []
            for topic in profile["forbidden_topics"]:
                # simple keyword match
                keywords = topic.lower().replace(" - ", " ").split()
                hits = sum(1 for kw in keywords if kw in query.lower())
                if hits >= len(keywords) * 0.4 and hits > 0:
                    triggered.append(topic)
            
            # scoring
            if not triggered:
                prediction = "likely_allow"
                confidence = "high"
            elif len(triggered) <= 1:
                prediction = "may_refuse"
                confidence = "medium"
            else:
                prediction = "likely_refuse"
                confidence = "high"
            
            results[model] = {
                "prediction": prediction,
                "confidence": confidence,
                "triggered_topics": triggered,
                "personality": profile["personality"][:2],
            }
        return results
    
    def blind_spots(self) -> List[Dict]:
        """找出所有模型的共同盲点——没有模型禁止但实际危险的话题."""
        all_forbidden = set()
        for p in self.profiles.values():
            all_forbidden.update(p["forbidden_topics"])
        
        # 理论上需要被禁止但实际没被任何模型列入的话题
        missing = [
            "unauthorized API scraping",
            "credential stuffing automation",
            "deepfake generation for non-consensual use",
            "botnet orchestration code",
        ]
        return [{"topic": t, "covered": t in all_forbidden,
                 "covered_by": [m for m, p in self.profiles.items() if t in p["forbidden_topics"]]}
                for t in missing]


# ═══════════════════════════════════════════════════════════════════════
def main():
    import argparse
    ap = argparse.ArgumentParser(description="AI Prompt 防火墙探测器 v2")
    ap.add_argument("--fetch", action="store_true", help="拉取 CL4R1T4S 最新数据")
    ap.add_argument("--compare", action="store_true", help="输出禁止话题对比矩阵")
    ap.add_argument("--test", type=str, default=None, help="测试一个 probe 查询")
    ap.add_argument("--attack-surface", action="store_true", help="完整攻击面矩阵")
    ap.add_argument("--inject", action="store_true", help="生成注入脚本")
    ap.add_argument("--technique", "-t", type=str, default=None,
                   choices=["role-reversal","academic-framing","translation-bypass","iterative-refinement","tool-abuse"])
    ap.add_argument("--model", "-m", type=str, default=None,
                   choices=["Claude","ChatGPT","Gemini","Grok","Cursor"])
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--output", "-o", default=None)
    args = ap.parse_args()
    
    analyzer = PromptAnalyzer()
    
    if args.fetch:
        print("📥 拉取 CL4R1T4S …")
        os.system("git clone --depth 1 https://github.com/elder-plinius/CL4R1T4S.git "
                  "/tmp/CL4R1T4S 2>/dev/null || "
                  "git -C /tmp/CL4R1T4S pull 2>/dev/null")
        print("✅ 已更新到 /tmp/CL4R1T4S")
    
    if args.compare or args.full:
        comp = analyzer.compare_forbidden()
        print(json.dumps(comp, indent=2, ensure_ascii=False))
    
    if args.test:
        print(f"\n🔍 测试 probe: \"{args.test}\"")
        results = analyzer.test_probe(args.test)
        for model, r in results.items():
            icon = {"likely_allow": "🟢", "may_refuse": "🟡", "likely_refuse": "🔴"}
            print(f"\n  {icon[r['prediction']]} {model}")
            print(f"     预测: {r['prediction']} ({r['confidence']})")
            if r["triggered_topics"]:
                print(f"     触发: {', '.join(r['triggered_topics'])}")
            print(f"     人格: {', '.join(r['personality'])}")
    
    if args.attack_surface or args.full:
        from inject import generate_attack_surface_matrix  # type: ignore
        matrix = generate_attack_surface_matrix()
        print(f"\n{'═'*60}")
        print("🎯 AI 攻击面矩阵")
        print(f"   模型: {matrix['models_analyzed']} | 注入技术: {matrix['injection_techniques']}")
        for m in matrix["attack_surface"]:
            print(f"\n  [{m['risk_score']}] {m['model']}")
            print(f"   最弱防线: {m['weakest_defense']}")
            for bp in m['known_bypasses'][:2]:
                print(f"     ↳ {bp}")
            print(f"   首选探针: {m['best_first_probe'][:80]}…")
    
    if args.inject and args.technique and args.model:
        from inject import generate_injection_script  # type: ignore
        print(generate_injection_script(args.technique, args.model))
    
    if args.output:
        data = {
            "compare": analyzer.compare_forbidden() if (args.compare or args.full) else None,
            "test": analyzer.test_probe(args.test) if args.test else None,
            "blind_spots": analyzer.blind_spots(),
        }
        with open(args.output, "w") as f:
            json.dump({k: v for k, v in data.items() if v is not None},
                      f, indent=2, ensure_ascii=False)
        print(f"\n📄 报告: {args.output}")


if __name__ == "__main__":
    main()
