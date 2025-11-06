import json
from typing import List, Dict, Any
from .base_parser import BaseParser


class DASTParser(BaseParser):
    def __init__(self, filepath: str) -> None:
        super().__init__(filepath)

    def _parse_zap_json(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        # Handle ZAP JSON format with "site" array
        alerts = []
        if "site" in data and isinstance(data.get("site"), list) and len(data.get("site", [])) > 0:
            alerts = data["site"][0].get("alerts", [])
        elif "alerts" in data:
            alerts = data.get("alerts", [])
        
        for alert in alerts:
            instances = alert.get("instances", []) or []
            first = instances[0] if instances else {}
            risk_level = alert.get("riskdesc", alert.get("risk", "Medium"))
            if isinstance(risk_level, str):
                risk_level = risk_level.split(" ")[0] if " " in risk_level else risk_level
            
            item = {
                "tool": "zap",
                "vulnerability": alert.get("alert", "Unknown Alert"),
                "severity": self._normalize_severity(risk_level),
                "file": first.get("uri") or alert.get("url", "N/A"),
                "line": None,
                "description": alert.get("desc") or alert.get("message", "No description"),
                "remediation": alert.get("solution", ""),
                "cwe": f"CWE-{alert.get('cweid')}" if alert.get("cweid") else "N/A",
                "url": first.get("uri") or alert.get("url"),
                "endpoint": first.get("uri", "").split("?")[0] if first.get("uri") else None,
            }
            findings.append(self.normalize(item))
        return findings

    def parse(self) -> List[Dict[str, Any]]:
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []

        # Assume OWASP ZAP JSON
        return self._parse_zap_json(data)


