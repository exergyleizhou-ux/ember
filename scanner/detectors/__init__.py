"""检测器注册表包。

导入本包即触发各检测器模块的注册(@register)。
对外暴露: Detector / register / iter_detectors / get。
"""

# 导入各检测器模块以触发注册(顺序即默认运行顺序)
from . import jwt, legacy  # noqa: E402,F401
from .base import Detector, get, iter_detectors, register

__all__ = ["Detector", "register", "iter_detectors", "get"]
