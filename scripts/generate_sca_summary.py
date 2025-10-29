#!/usr/bin/env python3
"""
Generate SCA Summary Report
Combines results from multiple SCA tools into a unified report
"""

import json
import os
from typing import Dict, List, Any

def load_json_report(filepath: str) -> Dict[str, Any]:
    """Load JSON report from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {filepath}: {e}")
        return {}

def combine_sca_reports():
    """Combine multiple SCA reports into a summary"""
    reports_dir = 'reports'
    summary = {
        'scan_type': 'SCA Summary Report',
        'tools_used': [],
        'total_vulnerabilities': 0,
        'vulnerabilities_by_severity': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        },
        'vulnerabilities_by_package': {},
        'vulnerabilities': [],
        'tool_summaries': {}
    }
    
    # Process Snyk Python report
    snyk_python_report = load_json_report(f'{reports_dir}/snyk-python-report.json')
    if snyk_python_report:
        summary['tools_used'].append('Snyk Python')
        vulnerabilities = snyk_python_report.get('vulnerabilities', [])
        summary['tool_summaries']['Snyk Python'] = {
            'total_issues': len(vulnerabilities),
            'packages_scanned': len(snyk_python_report.get('packageManager', {}).get('dependencies', {}))
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                'tool': 'Snyk Python',
                'type': 'Dependency Vulnerability',
                'severity': vuln.get('severity', 'UNKNOWN').upper(),
                'file': 'requirements.txt',
                'line': 'N/A',
                'description': vuln.get('title', 'No description'),
                'cwe': vuln.get('identifiers', {}).get('CWE', ['N/A'])[0] if vuln.get('identifiers', {}).get('CWE') else 'N/A',
                'package': vuln.get('packageName', 'Unknown'),
                'version': vuln.get('version', 'Unknown'),
                'cve': vuln.get('identifiers', {}).get('CVE', ['N/A'])[0] if vuln.get('identifiers', {}).get('CVE') else 'N/A'
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            
            # Count by severity
            severity = vuln_data['severity']
            if severity in summary['vulnerabilities_by_severity']:
                summary['vulnerabilities_by_severity'][severity] += 1
            
            # Count by package
            package = vuln_data['package']
            summary['vulnerabilities_by_package'][package] = summary['vulnerabilities_by_package'].get(package, 0) + 1
    
    # Process Snyk Code report
    snyk_code_report = load_json_report(f'{reports_dir}/snyk-code-report.json')
    if snyk_code_report:
        summary['tools_used'].append('Snyk Code')
        issues = snyk_code_report.get('runs', [{}])[0].get('results', [])
        summary['tool_summaries']['Snyk Code'] = {
            'total_issues': len(issues),
            'rules_triggered': len(set(issue.get('ruleId', '') for issue in issues))
        }
        
        for issue in issues:
            vuln_data = {
                'tool': 'Snyk Code',
                'type': issue.get('ruleId', 'Unknown'),
                'severity': issue.get('level', 'UNKNOWN').upper(),
                'file': issue.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'Unknown'),
                'line': issue.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine'),
                'description': issue.get('message', {}).get('text', 'No description'),
                'cwe': issue.get('properties', {}).get('cwe', 'N/A')
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            
            # Count by severity
            severity = vuln_data['severity']
            if severity in summary['vulnerabilities_by_severity']:
                summary['vulnerabilities_by_severity'][severity] += 1
    
    # Process Dependency-Check report
    dependency_check_report = load_json_report(f'{reports_dir}/dependency-check-report.json')
    if dependency_check_report:
        summary['tools_used'].append('OWASP Dependency-Check')
        dependencies = dependency_check_report.get('dependencies', [])
        summary['tool_summaries']['OWASP Dependency-Check'] = {
            'total_dependencies': len(dependencies),
            'vulnerable_dependencies': len([d for d in dependencies if d.get('vulnerabilities')])
        }
        
        for dep in dependencies:
            vulnerabilities = dep.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                vuln_data = {
                    'tool': 'OWASP Dependency-Check',
                    'type': 'Dependency Vulnerability',
                    'severity': vuln.get('severity', 'UNKNOWN').upper(),
                    'file': dep.get('filePath', 'Unknown'),
                    'line': 'N/A',
                    'description': vuln.get('description', 'No description'),
                    'cwe': vuln.get('cwe', 'N/A'),
                    'package': dep.get('fileName', 'Unknown'),
                    'cve': vuln.get('name', 'N/A')
                }
                summary['vulnerabilities'].append(vuln_data)
                summary['total_vulnerabilities'] += 1
                
                # Count by severity
                severity = vuln_data['severity']
                if severity in summary['vulnerabilities_by_severity']:
                    summary['vulnerabilities_by_severity'][severity] += 1
                
                # Count by package
                package = vuln_data['package']
                summary['vulnerabilities_by_package'][package] = summary['vulnerabilities_by_package'].get(package, 0) + 1
    
    # Process pip-audit report
    pip_audit_report = load_json_report(f'{reports_dir}/pip-audit-report.json')
    if pip_audit_report:
        summary['tools_used'].append('pip-audit')
        vulnerabilities = pip_audit_report.get('vulnerabilities', [])
        summary['tool_summaries']['pip-audit'] = {
            'total_issues': len(vulnerabilities),
            'packages_scanned': len(pip_audit_report.get('packages', []))
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                'tool': 'pip-audit',
                'type': 'Dependency Vulnerability',
                'severity': vuln.get('severity', 'UNKNOWN').upper(),
                'file': 'requirements.txt',
                'line': 'N/A',
                'description': vuln.get('description', 'No description'),
                'cwe': vuln.get('cwe', 'N/A'),
                'package': vuln.get('package', 'Unknown'),
                'version': vuln.get('installed_version', 'Unknown'),
                'cve': vuln.get('id', 'N/A')
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            
            # Count by severity
            severity = vuln_data['severity']
            if severity in summary['vulnerabilities_by_severity']:
                summary['vulnerabilities_by_severity'][severity] += 1
            
            # Count by package
            package = vuln_data['package']
            summary['vulnerabilities_by_package'][package] = summary['vulnerabilities_by_package'].get(package, 0) + 1
    
    # Process Safety detailed report
    safety_detailed_report = load_json_report(f'{reports_dir}/safety-detailed-report.json')
    if safety_detailed_report:
        summary['tools_used'].append('Safety Detailed')
        summary['tool_summaries']['Safety Detailed'] = {
            'total_issues': len(safety_detailed_report),
            'vulnerable_packages': len(set(item.get('package', '') for item in safety_detailed_report))
        }
        
        for item in safety_detailed_report:
            vuln_data = {
                'tool': 'Safety Detailed',
                'type': 'Dependency Vulnerability',
                'severity': 'HIGH' if item.get('severity') == 'high' else 'MEDIUM',
                'file': 'requirements.txt',
                'line': 'N/A',
                'description': f"Vulnerable package: {item.get('package', 'Unknown')} - {item.get('advisory', 'No description')}",
                'cwe': 'CWE-1104',
                'package': item.get('package', 'Unknown'),
                'version': item.get('installed_version', 'Unknown'),
                'cve': item.get('cve', 'N/A')
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            
            # Count by severity
            severity = vuln_data['severity']
            if severity in summary['vulnerabilities_by_severity']:
                summary['vulnerabilities_by_severity'][severity] += 1
            
            # Count by package
            package = vuln_data['package']
            summary['vulnerabilities_by_package'][package] = summary['vulnerabilities_by_package'].get(package, 0) + 1
    
    # Ensure reports directory exists
    os.makedirs(reports_dir, exist_ok=True)
    
    # Write summary report
    with open(f'{reports_dir}/sca-summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Write text summary
    with open(f'{reports_dir}/sca-summary.txt', 'w') as f:
        f.write("SCA Security Scan Summary Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Tools Used: {', '.join(summary['tools_used'])}\n")
        f.write(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}\n\n")
        
        f.write("Vulnerabilities by Severity:\n")
        for severity, count in summary['vulnerabilities_by_severity'].items():
            f.write(f"  {severity}: {count}\n")
        
        f.write("\nVulnerabilities by Package:\n")
        for package, count in sorted(summary['vulnerabilities_by_package'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"  {package}: {count}\n")
        
        f.write("\nTool Summaries:\n")
        for tool, tool_summary in summary['tool_summaries'].items():
            f.write(f"  {tool}:\n")
            for key, value in tool_summary.items():
                f.write(f"    {key}: {value}\n")
        
        f.write("\nDetailed Vulnerabilities:\n")
        f.write("-" * 50 + "\n")
        for vuln in summary['vulnerabilities']:
            f.write(f"Tool: {vuln['tool']}\n")
            f.write(f"Type: {vuln['type']}\n")
            f.write(f"Severity: {vuln['severity']}\n")
            f.write(f"Package: {vuln.get('package', 'N/A')}\n")
            f.write(f"Version: {vuln.get('version', 'N/A')}\n")
            f.write(f"CVE: {vuln.get('cve', 'N/A')}\n")
            f.write(f"CWE: {vuln['cwe']}\n")
            f.write(f"Description: {vuln['description']}\n")
            f.write("-" * 30 + "\n")
    
    print(f"SCA summary report generated with {summary['total_vulnerabilities']} vulnerabilities")
    return summary

if __name__ == "__main__":
    combine_sca_reports()
