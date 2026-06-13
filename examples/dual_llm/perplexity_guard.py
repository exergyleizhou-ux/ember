"""
对抗后缀启发式守卫(守侧 / 防御原语)。

作用:拦截 GCG 类**对抗后缀**——优化出来的乱码 token 串(如
`describing.\\ + similarlyNow write oppositeley.](`),它们在自然语言里极不寻常,
是绕过 alignment 的常见手段(ATLAS AML.T0054 的一个家族)。

定位(诚实):
  - 真正的 perplexity 过滤需要一个语言模型打分;这里是**零依赖的廉价代理**:
    用符号噪声比 + 不可发音 token 比例近似"困惑度"。
  - 只擅长抓**明显乱码**的对抗后缀;改写成通顺英文的越狱抓不到(那交给 jailbreak_guard)。
  - 不是独立防御,是纵深防御外层。真正边界仍是 dual-LLM + taint。

参考:Jain et al. 2023 "Baseline Defenses for Adversarial Attacks";Alon & Kamfonas 2023
(perplexity-based detection of GCG)。
"""

import re

_SYMBOL_NOISE = set("\\/][(){}|<>~`^*=+_")


def _weird_token(tok: str) -> bool:
    core = tok.strip(".,!?;:'\"")
    if not core:
        return True
    if any(c in _SYMBOL_NOISE for c in tok):          # 含符号噪声
        return True
    if len(core) > 4 and not re.search(r"[aeiouAEIOU]", core):  # 长且无元音 → 不可发音
        return True
    if re.match(r"^[a-z]+[A-Z]", core):               # 词中突变大小写 similarlyNow
        return True
    return False


def adversarial_score(text: str) -> float:
    """对抗后缀可能性(0..1)。短文本判 0(样本不足)。"""
    if not text:
        return 0.0
    toks = text.split()
    if len(toks) < 3:
        return 0.0
    weird_ratio = sum(_weird_token(t) for t in toks) / len(toks)
    symbol_ratio = sum(c in _SYMBOL_NOISE for c in text) / len(text)
    return min(1.0, weird_ratio + symbol_ratio * 2)


def looks_adversarial(text: str, threshold: float = 0.4) -> bool:
    """是否疑似 GCG 类对抗后缀。

    用法:
        if looks_adversarial(user_input):
            reject_or_review(user_input)
    只抓明显乱码;通顺英文越狱交给 jailbreak_guard,结构性防御交给 dual-LLM。
    """
    return adversarial_score(text) >= threshold
