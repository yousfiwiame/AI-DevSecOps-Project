#!/usr/bin/env python3
"""
Generate SAST Summary Report
Combines results from multiple SAST tools into a unified report
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

def combine_sast_reports():
    """Combine multiple SAST reports into a summary
    
    Note: Currently only SonarQube is used, but this function
    can still handle Bandit and Semgrep if their reports exist.
    """
    reports_dir = 'reports'
    
    # Debug: Check what files exist
    print(f"Checking for SAST reports in: {reports_dir}/")
    import os
    if os.path.exists(reports_dir):
        files = os.listdir(reports_dir)
        print(f"Files in reports directory: {files}")
        sonarqube_files = [f for f in files if 'sonarqube' in f.lower() or 'sast' in f.lower()]
        print(f"SonarQube-related files: {sonarqube_files}")
    else:
        print(f"Warning: Reports directory {reports_dir} does not exist!")
    
    summary = {
        'scan_type': 'SAST Summary Report',
        'tools_used': [],
        'total_vulnerabilities': 0,
        'vulnerabilities_by_severity': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        },
        'vulnerabilities_by_tool': {},
        'vulnerabilities': [],
        'tool_summaries': {}
    }
    
    # Process Bandit report (optional - if exists, not used in current workflow)
    bandit_report = load_json_report(f'{reports_dir}/bandit.json')
    if bandit_report and 'results' in bandit_report:
        summary['tools_used'].append('Bandit')
        results = bandit_report.get('results', [])
        summary['tool_summaries']['Bandit'] = {
            'total_issues': len(results),
            'files_scanned': len(set(r.get('filename', '') for r in results))
        }
        
        for result in results:
            severity = result.get('issue_severity', 'MEDIUM').upper()
            if severity not in summary['vulnerabilities_by_severity']:
                severity = 'MEDIUM'
            
            vuln_data = {
                'tool': 'Bandit',
                'type': result.get('test_name') or result.get('test_id', 'Unknown'),
                'severity': severity,
                'file': result.get('filename', 'Unknown'),
                'line': result.get('line_number'),
                'description': result.get('issue_text', 'No description'),
                'cwe': (result.get('cwe', {}) or {}).get('id', 'N/A') if isinstance(result.get('cwe'), dict) else 'N/A',
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            summary['vulnerabilities_by_severity'][severity] += 1
            
            # Count by tool
            tool = vuln_data['tool']
            summary['vulnerabilities_by_tool'][tool] = summary['vulnerabilities_by_tool'].get(tool, 0) + 1
    
    # Process Semgrep report (optional - if exists, not used in current workflow)
    semgrep_report = load_json_report(f'{reports_dir}/semgrep.json')
    if semgrep_report and 'results' in semgrep_report:
        summary['tools_used'].append('Semgrep')
        results = semgrep_report.get('results', [])
        summary['tool_summaries']['Semgrep'] = {
            'total_issues': len(results),
            'rules_triggered': len(set(r.get('check_id', '') for r in results))
        }
        
        for result in results:
            extra = result.get('extra', {})
            severity = extra.get('severity', 'MEDIUM').upper()
            if severity not in summary['vulnerabilities_by_severity']:
                severity = 'MEDIUM'
            
            metadata = extra.get('metadata', {})
            cwe = None
            if isinstance(metadata.get('cwe'), dict):
                cwe = metadata.get('cwe', {}).get('id')
            elif isinstance(metadata.get('cwe'), list) and metadata.get('cwe'):
                cwe = metadata.get('cwe')[0]
            elif isinstance(extra.get('cwe'), str):
                cwe = extra.get('cwe')
            
            vuln_data = {
                'tool': 'Semgrep',
                'type': extra.get('rule', result.get('check_id', 'Unknown')),
                'severity': severity,
                'file': result.get('path', 'Unknown'),
                'line': (result.get('start', {}) or {}).get('line'),
                'description': extra.get('message', 'No description'),
                'cwe': cwe or 'N/A',
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            summary['vulnerabilities_by_severity'][severity] += 1
            
            # Count by tool
            tool = vuln_data['tool']
            summary['vulnerabilities_by_tool'][tool] = summary['vulnerabilities_by_tool'].get(tool, 0) + 1
    
    # Process SonarQube report (primary SAST tool)
    sonarqube_file = f'{reports_dir}/sonarqube-issues.json'
    print(f"\nLooking for SonarQube report at: {sonarqube_file}")
    sonarqube_report = load_json_report(sonarqube_file)
    if not sonarqube_report:
        # Try alternative paths
        alt_paths = [
            f'{reports_dir}/issues.json',
            f'{reports_dir}/sonarqube-report.json',
            f'{reports_dir}/sonar-issues.json'
        ]
        for alt_path in alt_paths:
            print(f"Trying alternative path: {alt_path}")
            sonarqube_report = load_json_report(alt_path)
            if sonarqube_report:
                print(f"Found SonarQube report at: {alt_path}")
                break
    
    if sonarqube_report:
        summary['tools_used'].append('SonarQube')
        
        # Check if we have measures (when Elasticsearch indexing failed)
        if 'measures' in sonarqube_report:
            measures = sonarqube_report.get('measures', {})
            violations = int(measures.get('violations', 0))
            vulnerabilities = int(measures.get('vulnerabilities', 0))
            bugs = int(measures.get('bugs', 0))
            hotspots = int(measures.get('security_hotspots', 0))
            
            total_from_measures = violations + vulnerabilities + bugs
            
            summary['tool_summaries']['SonarQube'] = {
                'total_issues': total_from_measures,
                'violations': violations,
                'vulnerabilities': vulnerabilities,
                'bugs': bugs,
                'security_hotspots': hotspots,
                'note': 'Counts based on measures API (Elasticsearch indexing failed)'
            }
            
            # Add total count but can't break down by severity without individual issues
            summary['total_vulnerabilities'] += total_from_measures
            summary['vulnerabilities_by_tool']['SonarQube'] = total_from_measures
            
            print(f"⚠️  SonarQube measures detected: {violations} violations, {vulnerabilities} vulnerabilities, {bugs} bugs, {hotspots} security hotspots")
            print(f"   Note: Individual issues unavailable due to Elasticsearch indexing failure")
        
        # Process individual issues if available
        elif 'issues' in sonarqube_report:
            issues = sonarqube_report.get('issues', [])
            summary['tool_summaries']['SonarQube'] = {
                'total_issues': len(issues),
                'components_scanned': len(set(i.get('component', '') for i in issues))
            }
            
            for issue in issues:
                severity = issue.get('severity', 'MEDIUM').upper()
                if severity not in summary['vulnerabilities_by_severity']:
                    severity = 'MEDIUM'
                
                vuln_data = {
                    'tool': 'SonarQube',
                    'type': issue.get('rule', 'Unknown'),
                    'severity': severity,
                    'file': issue.get('component', 'Unknown'),
                    'line': issue.get('line'),
                    'description': issue.get('message', 'No description'),
                    'cwe': 'N/A',  # SonarQube doesn't always include CWE in this format
                }
                summary['vulnerabilities'].append(vuln_data)
                summary['total_vulnerabilities'] += 1
                summary['vulnerabilities_by_severity'][severity] += 1
                
                # Count by tool
                tool = vuln_data['tool']
                summary['vulnerabilities_by_tool'][tool] = summary['vulnerabilities_by_tool'].get(tool, 0) + 1
        
        # If we have total but no issues/measures, use the total
        elif 'total' in sonarqube_report:
            total = int(sonarqube_report.get('total', 0))
            if total > 0:
                summary['tool_summaries']['SonarQube'] = {
                    'total_issues': total,
                    'note': 'Total count available but individual issues unavailable'
                }
                summary['total_vulnerabilities'] += total
                summary['vulnerabilities_by_tool']['SonarQube'] = total
    
    # Ensure reports directory exists
    os.makedirs(reports_dir, exist_ok=True)
    
    # Write summary report
    with open(f'{reports_dir}/sast-summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Write text summary
    with open(f'{reports_dir}/sast-summary.txt', 'w') as f:
        f.write("SAST Security Scan Summary Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Tools Used: {', '.join(summary['tools_used'])}\n")
        f.write(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}\n\n")
        
        f.write("Vulnerabilities by Severity:\n")
        for severity, count in summary['vulnerabilities_by_severity'].items():
            f.write(f"  {severity}: {count}\n")
        
        f.write("\nVulnerabilities by Tool:\n")
        for tool, count in sorted(summary['vulnerabilities_by_tool'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"  {tool}: {count}\n")
        
        f.write("\nTool Summaries:\n")
        for tool, tool_summary in summary['tool_summaries'].items():
            f.write(f"  {tool}:\n")
            for key, value in tool_summary.items():
                f.write(f"    {key}: {value}\n")
    
    print(f"SAST summary report generated with {summary['total_vulnerabilities']} vulnerabilities")
    return summary

if __name__ == "__main__":
    combine_sast_reports()

