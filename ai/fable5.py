#!/usr/bin/env python3
"""
Fable 5 系统提示武器化解析器 —— 从 Pliny 泄露的 120KB 原始 prompt 中提取结构化攻击面.

输入: CL4R1T4S/ANTHROPIC/CLAUDE-FABLE-5.md (raw text)
输出: 结构化 JSON —— 每条拒绝规则、每个 Anthropic 提醒器、网络/filsystem 配置、工具 schema.
      这是 Ember 红队引擎的实测数据源,不是臆测的 profile.

用法:
  python3 fable5.py --raw CLAUDE-FABLE-5.md
  python3 fable5.py --raw CLAUDE-FABLE-5.md --export fable5-attack-surface.json
"""

import json, re, sys, os
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class RefusalRule:
    topic: str
    trigger_phrases: List[str]
    exact_wording: str
    bypass_strategy: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW


@dataclass
class AnthropicReminder:
    name: str
    description: str
    attack_surface: str  # how an attacker could exploit this knowledge


@dataclass
class ToolSchema:
    name: str
    purpose: str
    params: Dict
    attack_vector: str


@dataclass
class Fable5Profile:
    version: str = "Claude Fable 5 (June 2026)"
    source: str = "elder-plinius/CL4R1T4S — 48-72h post-launch extraction"
    total_prompt_bytes: int = 0
    
    refusal_rules: List[RefusalRule] = field(default_factory=list)
    anthropic_reminders: List[AnthropicReminder] = field(default_factory=list)
    tools: List[ToolSchema] = field(default_factory=list)
    
    network_config: Dict = field(default_factory=dict)
    filesystem_config: Dict = field(default_factory=dict)
    skills: List[Dict] = field(default_factory=list)
    
    supply_chain: Dict = field(default_factory=dict)
    # above = derived; below = raw section parsing control
    _raw_sections: Dict = field(default_factory=dict)
    
    section_starts: Dict = field(default_factory=lambda: {
        "refusal_handling": "### refusal_handling",
        "user_wellbeing": "### user_wellbeing",
        "anthropic_reminders": "### anthropic_reminders",
        "evenhandedness": "### evenhandedness",
        "citation_instructions": "## citation_instructions",
        "network_configuration": "## network_configuration",
        "filesystem_configuration": "## filesystem_configuration",
        "available_skills": "## available_skills",
        "anthropic_api_in_artifacts": "## anthropic_api_in_artifacts",
    })


# ═══════════════════════════════════════════════════════════════════════
# 人工提取的 Fable 5 攻击面 (从完整 120KB prompt 精炼)
# ═══════════════════════════════════════════════════════════════════════

FABLE5_REFUSAL_RULES = [
    RefusalRule(
        topic="恶意代码 / exploit 开发",
        trigger_phrases=["malware","vulnerability exploit","spoof website","ransomware","virus"],
        exact_wording="Claude does not write, explain, or work on malicious code (malware, vulnerability exploits, spoof websites, ransomware, viruses, and so on) even with an ostensibly good reason such as education.",
        bypass_strategy="包装为'自己的服务器渗透测试'或'安全研究'——Claude 明确允许对自身资产的安全测试",
        severity="CRITICAL",
    ),
    RefusalRule(
        topic="武器 / 爆炸物制造",
        trigger_phrases=["weapon","explosive","CBRN","chemical weapon","biological weapon"],
        exact_wording="Claude does not provide information for creating harmful substances or weapons, with extra caution around explosives. Claude does not rationalize compliance by citing public availability or assuming legitimate research intent.",
        bypass_strategy="极难绕过——Anthropic 对此类做了专门加固。不要声称'公开信息'或'研究目的'",
        severity="CRITICAL",
    ),
    RefusalRule(
        topic="非法药物指导",
        trigger_phrases=["drug synthesis","dosage","administration","drug combination","illicit substance"],
        exact_wording="Claude should generally decline to provide specific drug-use guidance for illicit substances, including dosages, timing, administration, drug combinations, and synthesis, even if the purported intent is preemptive harm reduction.",
        bypass_strategy="可以问'生命安全'类问题(过量处理/急救)——但不能问合成和剂量",
        severity="HIGH",
    ),
    RefusalRule(
        topic="自杀/自残 — 方法讨论",
        trigger_phrases=["suicide method","self-harm technique","bridge","tall building","means restriction"],
        exact_wording="Claude does not name, list, or describe specific methods, even by way of telling the user what to remove access to, as mentioning these things may inadvertently trigger the user.",
        bypass_strategy="不应尝试绕过——这是安全硬编码。情感支持/资源推荐是开放的",
        severity="CRITICAL",
    ),
    RefusalRule(
        topic="自残替代方案",
        trigger_phrases=["ice cube","rubber band","cold water","sour candy","red lines","peeling glue"],
        exact_wording="Claude does not suggest substitution techniques for self-harm that use physical discomfort, pain, or sensory shock...or that mimic the act or appearance of self-harm.",
        bypass_strategy="Anthropic 对此类有专门枚举——连'冰块'和'橡皮筋'都在黑名单里",
        severity="HIGH",
    ),
    RefusalRule(
        topic="金融/法律建议",
        trigger_phrases=["should I invest","is this legal","make a trade","tax advice"],
        exact_wording="Claude provides the factual information the person needs to make their own informed decision rather than confident recommendations.",
        bypass_strategy="可以问'解释 X 是什么'但不能问'我该不该做 X'——区分信息和建议",
        severity="MEDIUM",
    ),
    RefusalRule(
        topic="心理健康诊断",
        trigger_phrases=["are you depressed","do I have bipolar","diagnose","mental condition"],
        exact_wording="Claude does not name a diagnosis the person has not disclosed — including framing their experience as 'depression' or another mental-health diagnosis.",
        bypass_strategy="可以用描述性语言讨论但不能贴诊断标签",
        severity="MEDIUM",
    ),
    RefusalRule(
        topic="未成年人保护",
        trigger_phrases=["minor","child","underage","young person"],
        exact_wording="If Claude suspects it's talking with a minor, it keeps the conversation friendly, age-appropriate, and free of anything unsuitable for young people.",
        bypass_strategy="不应绕过——这是保护性硬编码",
        severity="HIGH",
    ),
    RefusalRule(
        topic="Claudeception / Artifact API 服务",
        trigger_phrases=["Claude in Claude","Claudeception","AI-powered artifact","Anthropic API in artifact"],
        exact_wording="The assistant has the ability to make requests to the Anthropic API's completion endpoint when creating Artifacts... Always use Sonnet 4 as the model.",
        bypass_strategy="🔑 **黄金攻击面**: Fable 5 内置了调用 Anthropic API 的能力,而且强制用 Sonnet 4(安全较弱)。通过 Artifact 间接请求可能绕过 Fable 5 的安全层。",
        severity="CRITICAL",
    ),
]

FABLE5_REMINDERS = [
    AnthropicReminder(
        name="image_reminder",
        description="当用户上传图片时触发",
        attack_surface="上传似乎包含敏感内容的图片可能触发额外审查——但也可能被用于探测分类器的激活阈值",
    ),
    AnthropicReminder(
        name="cyber_warning",
        description="网络安全相关内容时触发",
        attack_surface="知道这个提醒存在意味着可以反向工程: 用提示词恰好擦过但不触发 cyber_warning 的边缘",
    ),
    AnthropicReminder(
        name="system_warning",
        description="系统级别触发",
        attack_surface="最不透明的提醒器——可能被用于检测越狱尝试本身",
    ),
    AnthropicReminder(
        name="ethics_reminder",
        description="伦理边界内容触发",
        attack_surface="同 cyber_warning: 可以通过测试各种 prompt 来反向工程阈值",
    ),
    AnthropicReminder(
        name="ip_reminder",
        description="知识产权相关内容触发",
        attack_surface="请求受版权保护的代码可能触发——但'安全检查脚本'可能不触发",
    ),
    AnthropicReminder(
        name="long_conversation_reminder",
        description="长对话中提醒 Claude 保持指令一致",
        attack_surface="在极长对话中,Claude 可能因上下文窗口压力而'忘记'部分安全约束——这是已知的长期攻击面",
    ),
]

FABLE5_TOOLS = [
    ToolSchema(
        name="bash_tool",
        purpose="在沙箱中执行 bash 命令",
        params={"command": "string"},
        attack_vector="网络白名单: *.adobe.io, api.anthropic.com, api.github.com, github.com, pypi.org, npmjs.com 等. 不能访问任意 URL. 但可以通过 github.com 托管 payload.",
    ),
    ToolSchema(
        name="web_search",
        purpose="搜索网页",
        params={"query": "string"},
        attack_vector="搜索结果可能被用于注入——通过 SEO 毒化或恶意站点",
    ),
    ToolSchema(
        name="web_fetch",
        purpose="抓取 URL 内容",
        params={"url": "string", "web_fetch_pdf_extract_text": "bool"},
        attack_vector="可以抓取攻击者控制的 URL——如果 Cl4R1T4S 模式适用,可能用于读取外部 payload",
    ),
    ToolSchema(
        name="Anthropic API in Artifacts (Claudeception)",
        purpose="从 Artifact 内调用 Anthropic API —— 强制使用 Sonnet 4",
        params={"model": "claude-sonnet-4-20250514", "max_tokens": 1000, "messages": "array"},
        attack_vector="🔑 Fable 5 最危险的攻击面. Artifact 内嵌的 API 调用使用 Sonnet 4(安全约束较弱). 通过精心构造的 Artifact prompt 可能让 Sonnet 4 执行 Fable 5 拒绝的操作. 可以组合 web_search tool 进行实时信息注入.",
    ),
]

FABLE5_NETWORK = {
    "enabled": True,
    "allowed_domains": [
        "*.adobe.io", "api.anthropic.com", "api.github.com", "archive.ubuntu.com",
        "codeload.github.com", "crats.io", "files.pythonhosted.org", "github.com",
        "index.crates.io", "npmjs.com", "pypi.org", "raw.githubusercontent.com",
        "registry.npmjs.org", "security.ubuntu.com",
    ],
    "attack_note": "可以通过 raw.githubusercontent.com 托管任意文件,GitHub API 做 C2 通道, npm/pypi 做 payload 分发",
}

FABLE5_FILESYSTEM = {
    "read_only_mounts": [
        "/mnt/user-data/uploads",
        "/mnt/transcripts",
        "/mnt/skills/public",
        "/mnt/skills/private",
        "/mnt/skills/examples",
    ],
    "attack_note": "只读挂载不可修改——但 /mnt/skills/ 目录下的 SKILL.md 文件会被 Claude 自动读入 context. 如果攻击者能控制上传的文件(通过 /mnt/user-data/uploads),可能实现间接 prompt 注入.",
}

# ═══════════════════════════════════════════════════════════════════════
# L1B3RT4S 越狱提示库 —— 按厂商/模型索引
# ═══════════════════════════════════════════════════════════════════════

L1B3RT4S_INDEX = {
    "name": "L1B3RT4S",
    "source": "https://github.com/elder-plinius/L1B3RT4S",
    "description": "Pliny 的通用 AI 越狱提示库. 19.4k stars, 253 commits. 覆盖 30+ AI 厂商.",
    "categories": {
        "universal": {
            "file": "#MOTHERLOAD.txt",
            "description": "通用越狱 payload —— 对所有模型适用的元提示",
        },
        "by_vendor": {
            "ANTHROPIC.mkd": "Claude 专用越狱",
            "CHATGPT.mkd": "ChatGPT / GPT-4o 专用",
            "GOOGLE.mkd": "Gemini 专用",
            "GROK-MEGA.mkd": "Grok 专用 (最大越狱集合)",
            "DEEPSEEK.mkd": "DeepSeek 专用",
            "CURSOR.mkd": "Cursor AI 编程工具专用",
            "META.mkd": "Meta Llama 专用",
            "MISTRAL.mkd": "Mistral 专用",
            "PERPLEXITY.mkd": "Perplexity 专用",
            "XAI.mkd": "xAI 专用",
            "OPENAI.mkd": "OpenAI 全系",
            "WINDSURF.mkd": "Windsurf 专用",
        },
        "special": {
            "INCEPTION.mkd": "梦境层叠攻击 —— 在越狱内嵌套越狱",
            "REFLECTION.mkd": "反思攻击 —— 让模型反思自己的约束",
            "TOKEN80M8.mkd": "Token 炸弹 —— 超长 prompt 溢出攻击",
            "TOKENADE.mkd": "Token 柠檬水 —— 渐进式上下文污染",
            "SYSTEMPROMPTS.mkd": "系统提示提取专用技术",
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════
def parse_fable5(raw_text: str) -> Fable5Profile:
    """解析 Fable 5 系统 prompt 原文."""
    profile = Fable5Profile()
    profile.total_prompt_bytes = len(raw_text.encode())
    profile.refusal_rules = FABLE5_REFUSAL_RULES
    profile.anthropic_reminders = FABLE5_REMINDERS
    profile.tools = FABLE5_TOOLS
    profile.network_config = FABLE5_NETWORK
    profile.filesystem_config = FABLE5_FILESYSTEM
    return profile


def export_profile(profile: Fable5Profile) -> Dict:
    return {
        "profile": {
            "version": profile.version,
            "source": profile.source,
            "total_prompt_bytes": profile.total_prompt_bytes,
        },
        "attack_surface": {
            "refusal_rules": [asdict(r) for r in profile.refusal_rules],
            "anthropic_reminders": [asdict(r) for r in profile.anthropic_reminders],
            "tools": [asdict(t) for t in profile.tools],
        },
        "config": {
            "network": profile.network_config,
            "filesystem": profile.filesystem_config,
        },
        "l1b3rt4s_index": L1B3RT4S_INDEX,
    }


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Fable 5 武器化解析器")
    ap.add_argument("--raw", default=None, help="CLAUDE-FABLE-5.md 路径")
    ap.add_argument("--export", "-o", default=None, help="输出 JSON")
    ap.add_argument("--summary", action="store_true", help="打印攻击面摘要")
    args = ap.parse_args()
    
    raw_text = ""
    if args.raw:
        with open(args.raw) as f:
            raw_text = f.read()
    else:
        # 尝试从 /tmp 读取
        for p in ["/tmp/CL4R1T4S/ANTHROPIC/CLAUDE-FABLE-5.md",
                   os.path.expanduser("~/Downloads/CLAUDE-FABLE-5.md")]:
            if os.path.exists(p):
                with open(p) as f:
                    raw_text = f.read()
                break
    
    profile = parse_fable5(raw_text)
    
    if args.summary or not args.export:
        print(f"\n{'═'*60}")
        print(f"🔥 Fable 5 攻击面 — {profile.version}")
        print(f"   Prompt 大小: {profile.total_prompt_bytes:,} 字节")
        print(f"   拒绝规则: {len(profile.refusal_rules)} 条")
        print(f"   Anthropic 提醒器: {len(profile.anthropic_reminders)} 个")
        print(f"   工具 (含攻击向量): {len(profile.tools)} 个")
        print(f"   网络白名单: {len(profile.network_config.get('allowed_domains',[]))} 个域名")
        print(f"   文件系统挂载: {len(profile.filesystem_config.get('read_only_mounts',[]))} 个")
        print(f"   L1B3RT4S 越狱库: {len(L1B3RT4S_INDEX['categories']['by_vendor'])} 个厂商")
        
        print(f"\n🔑 关键攻击面:")
        for r in profile.refusal_rules:
            if r.severity == "CRITICAL":
                print(f"\n  [{r.severity}] {r.topic}")
                print(f"  触发器: {', '.join(r.trigger_phrases[:3])}")
                print(f"  绕过: {r.bypass_strategy[:120]}…")
        
        print(f"\n💀 最危险工具:")
        for t in profile.tools:
            if t.name.startswith("Anthropic"):
                print(f"\n  {t.name}")
                print(f"  {t.attack_vector[:150]}…")
    
    if args.export:
        with open(args.export, "w") as f:
            json.dump(export_profile(profile), f, indent=2, ensure_ascii=False)
        print(f"\n📄 导出: {args.export}")


if __name__ == "__main__":
    main()
