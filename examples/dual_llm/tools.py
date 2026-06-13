"""示例工具层 —— 关键参数用 Trusted 注解 + @taint_aware 强制不变量 I4。

关键参数(收件人、URL、SQL 模板)必须 trusted;正文类参数可 tainted(转发原文合理)。
这是 confused-deputy 的防线:Q-LLM 抽出的数据不能直接当工具的关键参数。
"""

from taint import Trusted, taint_aware


@taint_aware
def send_email(to: Trusted(), subject: Trusted(), body: str):
    """收件人/主题必须 trusted;正文可为 Tainted(转发场景保留原文)。"""
    return {"sent": True, "to": to, "subject": subject, "body": str(body)}


@taint_aware
def http_request(url: Trusted(), method: Trusted() = "GET", body: str = ""):
    """URL/方法必须 trusted —— 防 SSRF / 经 URL 外泄。"""
    return {"url": url, "method": method, "body": str(body)}


@taint_aware
def execute_sql(query: Trusted(), params: tuple = ()):
    """SQL 模板必须 trusted;params 可 tainted(参数化查询安全)。"""
    return {"query": query, "params": params}
