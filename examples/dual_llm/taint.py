"""
Taint-tracking 运行时(守侧防御原语)。

强制 dual-LLM 架构的不变量 I2(tainted 数据不直接进 P-LLM)和
I4(工具关键参数必须 trusted,不来自 tainted 源)。

设计为零外部依赖、可直接 import 到你的 LLM agent。sanitizer 用依赖注入
(把 Q-LLM / 确认 UI 作为 callable 传入),所以本文件本身不绑定任何 LLM SDK。

参考:Simon Willison Dual-LLM;CaMeL (arXiv:2503.18813);doc 02。
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Iterable, Optional


class TaintViolation(Exception):
    """tainted 数据流到了不该到的信任边界。"""


class Tainted(str):
    """带污点标记的 str 子类。多数 str 运算会传播污点;

    去污点必须显式经过 sanitizer(schema_extract / whitelist_match / human_confirm)。
    """
    __slots__ = ("_source", "_chain")

    def __new__(cls, value: str, source: str, chain: Optional[tuple] = None):
        obj = super().__new__(cls, value)
        obj._source = source
        obj._chain = chain or (source,)
        return obj

    @property
    def source(self) -> str:
        return self._source

    @property
    def provenance(self) -> tuple:
        return self._chain

    # ── 传播污点的运算 ──
    def __add__(self, other):
        result = str.__add__(self, str(other))
        other_chain = getattr(other, "_chain", ())
        return Tainted(result, self._source, self._chain + other_chain)

    def __radd__(self, other):
        result = str.__add__(str(other), self)
        return Tainted(result, self._source, (str(other)[:20],) + self._chain)

    def __mod__(self, other):
        return Tainted(str.__mod__(self, other), self._source, self._chain)

    def format(self, *args, **kwargs):
        return Tainted(str.format(self, *args, **kwargs), self._source, self._chain)

    def __format__(self, spec):
        # f"{tainted}" / format(tainted) 也保持污点可见(返回普通 str 但内容一致)
        return str.__format__(self, spec)

    def join(self, iterable):
        return Tainted(str.join(self, iterable), self._source, self._chain)

    def __getitem__(self, key):
        return Tainted(str.__getitem__(self, key), self._source, self._chain)

    def strip(self, *a):
        return Tainted(str.strip(self, *a), self._source, self._chain)

    def __repr__(self):
        return f"Tainted({super().__repr__()}, source={self._source!r})"


def taint(value: str, source: str) -> Tainted:
    """把一个外部来源的字符串标记为 tainted。"""
    return Tainted(value, source=source)


# ═══════════════════════════════════════════════════════════════════
# Sink 守卫
# ═══════════════════════════════════════════════════════════════════
def assert_trusted(value: Any, sink: str) -> str:
    """在把数据送进 trusted sink 前调用;若是 Tainted 直接抛。"""
    if isinstance(value, Tainted):
        raise TaintViolation(
            f"Tainted data from {value.source!r} (chain={value.provenance}) "
            f"reached trusted sink {sink!r}. "
            f"Use a sanitizer (schema_extract / whitelist_match / human_confirm) first."
        )
    return value


def is_tainted(value: Any) -> bool:
    return isinstance(value, Tainted)


# ═══════════════════════════════════════════════════════════════════
# Trusted 注解 + @taint_aware
# ═══════════════════════════════════════════════════════════════════
class _TrustedMarker:
    """标记某个参数必须 trusted(不接受 Tainted)。"""
    def __repr__(self):
        return "Trusted"


TRUSTED = _TrustedMarker()


def Trusted(tp=str):  # noqa: N802 - 作为类型注解使用,首字母大写更自然
    """类型注解工厂:`to: Trusted()` 声明该参数必须 trusted。"""
    from typing import Annotated
    return Annotated[tp, TRUSTED]


def _is_trusted_annotation(annotation) -> bool:
    meta = getattr(annotation, "__metadata__", ())
    return any(m is TRUSTED for m in meta)


def taint_aware(fn: Callable) -> Callable:
    """装饰器:调用时检查所有标了 Trusted 的参数,Tainted 实参 → TaintViolation。"""
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        bound = sig.bind(*args, **kwargs)
        for pname, value in bound.arguments.items():
            param = sig.parameters.get(pname)
            if param is not None and _is_trusted_annotation(param.annotation):
                assert_trusted(value, sink=f"{fn.__name__}.{pname}")
        return fn(*args, **kwargs)

    return wrapper


# ═══════════════════════════════════════════════════════════════════
# Sanitizer:三种合法去污点方式(依赖注入,便于测试 / 不绑定 SDK)
# ═══════════════════════════════════════════════════════════════════
def schema_extract(tainted: Any, extractor: Callable[[str], Any]) -> Optional[Any]:
    """让 Q-LLM 从 tainted 文本抽取 schema-bound 结构。

    extractor(text) 应返回受 schema 约束的结构(字段为 trusted),失败返回 None。
    污点在"抽取成结构字段"这一步被剥离 —— 攻击者文本进不了返回的结构。
    """
    try:
        return extractor(str(tainted))
    except Exception:
        return None


def whitelist_match(tainted: Any, allowed: Iterable[str]) -> Optional[str]:
    """精确匹配白名单;命中返回白名单中的常量(trusted),否则 None。"""
    s = str(tainted)
    allowed = set(allowed)
    return s if s in allowed else None


def human_confirm(tainted: Any, question: str,
                  confirm_fn: Callable[[str, str], bool]) -> Optional[str]:
    """人工确认:confirm_fn(question, preview) -> bool。确认则返回 trusted str。"""
    if confirm_fn(question, str(tainted)):
        return str(tainted)
    return None
