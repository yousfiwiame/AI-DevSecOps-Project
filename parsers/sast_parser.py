import json
from typing import List, Dict, Any
from .base_parser import BaseParser


class SASTParser(BaseParser):
    def __init__(self, filepath: str) -> None:
        super().__init__(filepath)

    def _parse_bandit(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for res in data.get("results", []):
            item = {
                "tool": "bandit",
                "vulnerability": res.get("test_name") or res.get("test_id"),
                "severity": self._normalize_severity(res.get("issue_severity")),
                "file": res.get("filename"),
                "line": res.get("line_number"),
                "description": res.get("issue_text"),
                "cwe": (res.get("cwe", {}) or {}).get("id") or "N/A",
            }
            findings.append(self.normalize(item))
        return findings

    def _parse_semgrep(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for res in data.get("results", []):
            extra = res.get("extra", {})
            metadata = extra.get("metadata", {})
            cwe = None
            # Semgrep sometimes includes cwe metadata in various shapes
            if isinstance(metadata.get("cwe"), dict):
                cwe = metadata.get("cwe", {}).get("id")
            elif isinstance(metadata.get("cwe"), list) and metadata.get("cwe"):
                cwe = metadata.get("cwe")[0]
            elif isinstance(extra.get("cwe"), str):
                cwe = extra.get("cwe")

            item = {
                "tool": "semgrep",
                "vulnerability": extra.get("rule", res.get("check_id")),
                "severity": self._normalize_severity(extra.get("severity")),
                "file": res.get("path"),
                "line": (res.get("start", {}) or {}).get("line"),
                "description": extra.get("message"),
                "cwe": cwe or "N/A",
            }
            findings.append(self.normalize(item))
        return findings

    def parse(self) -> List[Dict[str, Any]]:
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []

        # Heuristics to detect producer
        if "results" in data and "generated_at" in data and "errors" in data and "metrics" in data:
            return self._parse_bandit(data)

        if "results" in data and isinstance(data.get("results"), list) and any("check_id" in r or "extra" in r for r in data.get("results", [])):
            return self._parse_semgrep(data)

        # Unknown producer
        return []


