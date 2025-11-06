"""
Common base parser providing normalization utilities for vulnerability findings.
"""
from typing import Dict, Any


class BaseParser:
    def __init__(self, report_path: str) -> None:
        self.report_path = report_path
        self.vulnerabilities = []

    def parse(self):
        raise NotImplementedError

    def _normalize_severity(self, severity: str) -> str:
        s = str(severity or "").upper()
        if s.startswith("CRIT"):
            return "CRITICAL"
        if s.startswith("HIGH"):
            return "HIGH"
        if s.startswith("MED") or s.startswith("MOD"):
            return "MEDIUM"
        if s.startswith("LOW") or s.startswith("INFO"):
            return "LOW"
        return "MEDIUM"

    def normalize(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize an item to a common schema. Accepts flexible inputs and maps
        them into a unified structure used by downstream scripts/LLM.
        """
        vulnerability = item.get("vulnerability") or item.get("type") or "Unknown"
        severity = self._normalize_severity(item.get("severity"))
        out: Dict[str, Any] = {
            "vulnerability": vulnerability,
            "severity": severity,
            "cwe": item.get("cwe", "N/A"),
            "file": item.get("file", "N/A"),
            "line": item.get("line"),
            "description": item.get("description", ""),
            "remediation": item.get("remediation", ""),
            "tool": item.get("tool", "Unknown"),
        }
        # Optional passthroughs
        for k in ("cve", "url", "endpoint", "dependency", "package", "version"):
            if k in item:
                out[k] = item[k]
        return out


