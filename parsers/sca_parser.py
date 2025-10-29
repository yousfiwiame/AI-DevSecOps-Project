"""
SCA (Dependency-Check) Report Parser
"""
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from .base_parser import BaseParser


class SCAParser(BaseParser):
    """Parser for OWASP Dependency-Check SCA reports"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse Dependency-Check report"""
        if self.report_path.endswith('.json'):
            return self.parse_json()
        elif self.report_path.endswith('.xml'):
            return self.parse_xml()
        else:
            raise ValueError(f"Unsupported file format: {self.report_path}")
    
    def parse_json(self) -> List[Dict[str, Any]]:
        """Parse JSON format report"""
        with open(self.report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.vulnerabilities = self.extract_vulnerabilities(data)
        return self.vulnerabilities
    
    def parse_xml(self) -> List[Dict[str, Any]]:
        """Parse XML format report"""
        tree = ET.parse(self.report_path)
        root = tree.getroot()
        
        # Convert XML to dict structure
        data = self.xml_to_dict(root)
        self.vulnerabilities = self.extract_vulnerabilities(data)
        return self.vulnerabilities
    
    def xml_to_dict(self, element):
        """Recursively convert XML to dictionary"""
        result = {'name': element.tag}
        
        if element.text and element.text.strip():
            result['text'] = element.text.strip()
        
        for child in element:
            child_result = self.xml_to_dict(child)
            if child.tag not in result:
                result[child.tag] = []
            result[child.tag].append(child_result)
        
        return result
    
    def extract_vulnerabilities(self, data: Any) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from SCA report"""
        vulnerabilities = []
        
        # Handle JSON structure
        if isinstance(data, dict):
            # Check if this is the unified SCA summary format (from generate_sca_summary.py)
            if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                # This is the sca-summary.json format
                for vuln in data['vulnerabilities']:
                    # Already in normalized format, just need to adjust structure
                    normalized = {
                        'vulnerability': vuln.get('type', 'Dependency Vulnerability'),
                        'severity': vuln.get('severity', 'UNKNOWN'),
                        'cwe': vuln.get('cwe', 'N/A'),
                        'file': vuln.get('file', 'requirements.txt'),
                        'line': vuln.get('line', 'N/A'),
                        'description': vuln.get('description', 'No description'),
                        'remediation': f"Update {vuln.get('package', 'dependency')} to latest secure version",
                        'cve': vuln.get('cve', 'N/A'),
                        'dependency': vuln.get('package', 'Unknown'),
                        'package': vuln.get('package', 'Unknown'),
                        'version': vuln.get('version', 'Unknown'),
                        'tool': vuln.get('tool', 'Unknown')
                    }
                    vulnerabilities.append(self.normalize(normalized))
            # Check if this is OWASP Dependency-Check format (fallback)
            elif 'dependencies' in data:
                # Legacy format - OWASP Dependency-Check structure
                dependencies = data.get('dependencies', [])
                for dep in dependencies:
                    vulns = dep.get('vulnerabilities', [])
                    for vuln in vulns:
                        normalized = self.normalize_dependency_vuln(vuln, dep)
                        vulnerabilities.append(self.normalize(normalized))
        
        return vulnerabilities
    
    def normalize_dependency_vuln(self, vuln: Dict, dep: Dict) -> Dict:
        """Normalize dependency vulnerability"""
        cves = vuln.get('name', vuln.get('cve', 'Unknown CVE'))
        severity = vuln.get('severity', 'HIGH')
        
        # Parse CVSS score if available
        cvss_score = vuln.get('cvssv3', {}).get('score', vuln.get('cvssScore', 0))
        if cvss_score >= 9.0:
            severity = 'CRITICAL'
        elif cvss_score >= 7.0:
            severity = 'HIGH'
        elif cvss_score >= 4.0:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        return {
            'vulnerability': f'Dependency Vulnerability: {cves}',
            'severity': severity,
            'cwe': vuln.get('cwe', 'CWE-937'),  # OWASP Top Ten - Using Components with Known Vulnerabilities
            'file': f"{dep.get('fileName', 'Unknown')} ({dep.get('filePath', 'Unknown')})",
            'line': 'N/A',
            'description': vuln.get('description', f'Known vulnerability in dependency: {cves}'),
            'remediation': f"Update {dep.get('fileName', 'dependency')} to version {self.suggest_version(vuln, dep)} or later",
            'cve': cves,
            'dependency': dep.get('fileName', 'Unknown')
        }
    
    def suggest_version(self, vuln: Dict, dep: Dict) -> str:
        """Suggest fix version"""
        # This would typically come from the report
        return dep.get('version', 'latest')
    
    def get_tool_name(self) -> str:
        return 'OWASP Dependency-Check'
