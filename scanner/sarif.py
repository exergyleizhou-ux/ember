#!/usr/bin/env python3
"""
把扫描报告转成 SARIF 2.1.0 —— 让结果能直接喂给 GitHub Code Scanning、
CI 流水线和其它安全工具。纯函数,无副作用,便于测试。

输入: scanner.Scanner.report() 的输出 dict(含 target / findings)。
输出: SARIF 2.1.0 dict。
"""

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# 漏洞 severity → SARIF level
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def severity_to_level(severity: str) -> str:
    return _LEVEL.get((severity or "").lower(), "note")


def to_sarif(report: dict, tool_version: str = "0.1.0", detector_meta: dict = None) -> dict:
    """report(scanner.report() 输出)→ SARIF 2.1.0。

    detector_meta: 可选,{check_name: {"owasp": ..., "atlas": ...}};
    若提供,则把 OWASP/ATLAS 标签写进规则的 properties.tags,供 SIEM/Code Scanning 消费。
    """
    findings = report.get("findings", [])
    meta = detector_meta or {}

    # 去重收集规则(按 check)
    rules = []
    seen = set()
    for f in findings:
        rule_id = f.get("check", "unknown")
        if rule_id in seen:
            continue
        seen.add(rule_id)
        m = meta.get(rule_id, {})
        tags = [t for t in (m.get("owasp"), m.get("atlas")) if t]
        rule = {
            "id": rule_id,
            "name": rule_id.replace("-", "_"),
            "shortDescription": {"text": f"Ember check: {rule_id}"},
        }
        if tags or m:
            rule["properties"] = {
                "tags": tags,
                "owasp": m.get("owasp", ""),
                "atlas": m.get("atlas", ""),
            }
        rules.append(rule)

    results = []
    for f in findings:
        uri = f.get("path", "") or "/"
        results.append({
            "ruleId": f.get("check", "unknown"),
            "level": severity_to_level(f.get("severity", "")),
            "message": {"text": f.get("detail", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }],
            "properties": {
                "severity": f.get("severity", ""),
                "method": f.get("method", ""),
                "evidence": f.get("evidence", ""),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Ember",
                    "informationUri": "https://github.com/exergyleizhou-ux/ember",
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "properties": {
                "target": report.get("target", ""),
                "scannedAt": report.get("scanned_at", ""),
            },
            "results": results,
        }],
    }
