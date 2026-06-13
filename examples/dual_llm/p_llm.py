"""Privileged LLM(P-LLM)封装 —— 唯一能调工具,prompt 必须 trusted。

运行时强制不变量 I2:tainted 数据不得直接进 P-LLM 的 prompt。
chat_fn 由调用方注入,本文件不绑定任何 SDK。
"""

from taint import assert_trusted


class PrivilegedLLM:
    def __init__(self, chat_fn):
        # chat_fn(prompt: str, tools: list) -> 计划(typed)
        self._chat_fn = chat_fn

    def plan(self, prompt, tools):
        # I2: prompt 里只能是 user 原始输入 + Q-LLM 抽出的 schema 字段(trusted)
        assert_trusted(prompt, sink="p_llm.prompt")
        return self._chat_fn(prompt, tools)
