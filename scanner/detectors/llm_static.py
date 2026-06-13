"""LLM 应用静态检测器(守侧 SAST,mode=static)。

扫你自己 agent 的 Python 源码,找违反 dual-LLM 不变量的数据流:
  - 外部不可信数据未经净化进 LLM 调用(间接注入面)
  - 外部数据流到危险/工具调用(confused deputy)
  - LLM 输出未净化就渲染(markdown/HTML 外泄)

需 `--source DIR`(扫源码),与打活目标的 HTTP 检测器互不影响。
"""

from llm_app.ast_taint import analyze

from .base import Detector, register


class _StaticLLMDetector(Detector):
    mode = "static"

    def run(self, ctx):
        files = getattr(ctx, "source_files", [])
        print(f"\n🔍 {self.name.upper()}: 扫 {len(files)} 个源码文件")
        for path, code in files:
            flows = [f for f in analyze(code, path) if f["rule"] == self.name]
            ctx.stats["total"] += 1
            if flows:
                for fl in flows:
                    ctx._add(self.severity, self.name, fl["file"], "static",
                             fl["snippet"], evidence=f"line {fl['line']} → {fl['sink']}")
            else:
                ctx.stats["passed"] += 1


@register
class IndirectInjectionDetector(_StaticLLMDetector):
    name = "llm-indirect-injection-sink"
    owasp = "LLM01:2025"
    atlas = "AML.T0051.001"
    severity = "high"


@register
class ToolConfusedDeputyDetector(_StaticLLMDetector):
    name = "llm-tool-confused-deputy"
    owasp = "LLM01:2025"
    atlas = "AML.T0053"
    severity = "high"


@register
class OutputExfilDetector(_StaticLLMDetector):
    name = "llm-output-exfil"
    owasp = "LLM02:2025"
    atlas = "AML.T0057"
    severity = "medium"


@register
class CodeExecDetector(_StaticLLMDetector):
    name = "llm-code-exec"
    owasp = "LLM05:2025"      # Improper Output Handling
    atlas = "AML.T0050"      # Command and Scripting Interpreter
    severity = "critical"    # LLM 输出被自动执行 = RCE


@register
class MultiAgentMessageDetector(_StaticLLMDetector):
    name = "llm-multi-agent-message-audit"
    owasp = "LLM01:2025"
    atlas = "AML.T0061"      # LLM Prompt Self-Replication
    severity = "high"        # 未净化数据跨 agent 传递 = 注入蠕虫面
