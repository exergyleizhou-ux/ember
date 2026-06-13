"""认证流取 token —— 从登录响应里提取 token,供需要鉴权的检测器(JWT 等)。

纯函数 extract_token 便于单测;Scanner 侧用它把 --login 流程拿到的 token 灌进 ctx.token。
"""

from collections import deque
from typing import Optional

# 常见的 token 字段名
COMMON_TOKEN_KEYS = (
    "access_token", "accessToken", "token", "jwt",
    "id_token", "idToken", "access", "authToken",
)


def _dig(obj, path: str) -> Optional[str]:
    """按点路径(如 data.tokens.access_token)取字符串值。"""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur if isinstance(cur, str) else None


def _bfs(obj, predicate) -> Optional[str]:
    q = deque([obj])
    while q:
        cur = q.popleft()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, str) and k in COMMON_TOKEN_KEYS and predicate(v):
                    return v
                if isinstance(v, (dict, list)):
                    q.append(v)
        elif isinstance(cur, list):
            q.extend(cur)
    return None


def extract_token(obj, path: Optional[str] = None) -> Optional[str]:
    """从登录响应里取 token。

    path 给定则按点路径取;否则自动发现:优先取 JWT 形状(含两个点)的常见字段,
    再退而取任意非空的常见字段。
    """
    if path:
        return _dig(obj, path)
    jwt_like = _bfs(obj, lambda v: v.count(".") >= 2)
    if jwt_like:
        return jwt_like
    return _bfs(obj, lambda v: bool(v))
