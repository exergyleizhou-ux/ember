"""Quarantined LLM(Q-LLM)封装 —— 处理不可信数据,只输出 schema-bound 结构。

无工具、无网络、无副作用。失败返回 None,绝不把攻击者文本传回 P-LLM。
extract_fn 由调用方注入(包你的小模型 + schema 校验),本文件不绑定任何 SDK。
"""

from taint import schema_extract


class QuarantinedLLM:
    def __init__(self, extract_fn):
        # extract_fn(text: str, schema) -> 结构化对象(字段 trusted);失败可抛异常
        self._extract_fn = extract_fn

    def extract(self, tainted, schema):
        """从 tainted 文本抽 schema 字段;返回 trusted 结构或 None。"""
        return schema_extract(tainted, lambda text: self._extract_fn(text, schema))
