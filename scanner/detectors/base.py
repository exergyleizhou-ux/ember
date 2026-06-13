"""检测器基类 + 注册表 —— 守侧检测器的统一接口。

每个检测器是一个小类:声明 name/owasp/severity,实现 run(ctx)。
ctx(ScanContext,由 Scanner 充当)提供共享的 HTTP 层(限速/重试/取头)、
端点分组、测试用户注册、记账 API —— 检测器不自己造 HTTP,统一受授权/限速约束。
"""

_REGISTRY = []


def register(cls):
    """类装饰器:把检测器登记进全局注册表。"""
    _REGISTRY.append(cls)
    return cls


def iter_detectors():
    """返回所有已注册检测器的实例。"""
    return [cls() for cls in _REGISTRY]


def get(name: str):
    """按 name 取一个检测器实例。"""
    for cls in _REGISTRY:
        if cls.name == name:
            return cls()
    raise KeyError(name)


class Detector:
    name: str = ""        # 唯一标识 → SARIF ruleId
    owasp: str = ""       # 对应 OWASP API 类别,如 "API2:2023"
    severity: str = "medium"
    slow: bool = False    # 慢检测器(--quick 时跳过)

    def run(self, ctx):
        raise NotImplementedError
