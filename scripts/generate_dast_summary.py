#!/usr/bin/env python3
"""
Generate DAST Summary Report
Combines results from OWASP ZAP reports into a unified summary
"""

import json
import os
import re
from typing import Dict, List, Any

def load_json_report(filepath: str) -> Dict[str, Any]:
    """Load JSON report from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {filepath}: {e}")
        return {}

def combine_dast_reports():
    """Combine DAST reports into a summary"""
    reports_dir = 'reports'
    
    # Debug: Check what files exist
    print(f"Checking for DAST reports in: {reports_dir}/")
    if os.path.exists(reports_dir):
        files = os.listdir(reports_dir)
        print(f"Files in reports directory: {files}")
        dast_files = [f for f in files if 'dast' in f.lower() or 'zap' in f.lower()]
        print(f"DAST-related files: {dast_files}")
    else:
        print(f"Warning: Reports directory {reports_dir} does not exist!")
    
    summary = {
        'scan_type': 'DAST Summary Report',
        'tools_used': [],
        'total_vulnerabilities': 0,
        'vulnerabilities_by_severity': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        },
        'vulnerabilities_by_type': {},
        'vulnerabilities': [],
        'tool_summaries': {}
    }
    
    # Process OWASP ZAP report (primary DAST tool)
    zap_file = f'{reports_dir}/dast-report.json'
    print(f"\nLooking for ZAP report at: {zap_file}")
    zap_report = load_json_report(zap_file)
    
    # Try alternative paths
    if not zap_report:
        alt_paths = [
            f'{reports_dir}/zap-report.json',
            f'{reports_dir}/dast-baseline-report.json',
            f'{reports_dir}/zap-baseline-report.json'
        ]
        for alt_path in alt_paths:
            print(f"Trying alternative path: {alt_path}")
            zap_report = load_json_report(alt_path)
            if zap_report:
                print(f"Found ZAP report at: {alt_path}")
                break
    
    if zap_report:
        # Handle ZAP JSON format
        alerts = []
        if isinstance(zap_report, dict):
            # ZAP format with "site" array
            if "site" in zap_report and isinstance(zap_report.get("site"), list):
                for site in zap_report["site"]:
                    if isinstance(site, dict) and "alerts" in site:
                        alerts.extend(site.get("alerts", []))
            # ZAP format with direct "alerts" key
            elif "alerts" in zap_report:
                alerts = zap_report.get("alerts", [])
    
    # If JSON report is empty but logs exist, parse from logs
    if not alerts or len(alerts) == 0:
        print("ZAP JSON report is empty or has no alerts. Attempting to parse from scan logs...")
        # Try to parse from ZAP scan logs
        # Check multiple possible locations
        current_dir = os.getcwd()
        log_files = [
            # Root directory
            'full_scan.log',
            'baseline_scan.log',
            # Reports directory
            f'{reports_dir}/full_scan.log',
            f'{reports_dir}/baseline_scan.log',
            # Parent of reports directory
            f'{reports_dir}/../full_scan.log',
            f'{reports_dir}/../baseline_scan.log',
            # Absolute paths if running in workflow
            os.path.join(current_dir, 'full_scan.log'),
            os.path.join(current_dir, 'baseline_scan.log'),
            os.path.join(current_dir, 'reports', 'full_scan.log'),
            os.path.join(current_dir, 'reports', 'baseline_scan.log'),
        ]
        
        zap_log_content = None
        found_log = None
        for log_file in log_files:
            try:
                if os.path.exists(log_file) and os.path.isfile(log_file):
                    with open(log_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if content and len(content) > 100:  # Ensure it's not empty
                            zap_log_content = content
                            found_log = log_file
                            print(f"✅ Found ZAP log at: {log_file} ({len(content)} bytes)")
                            break
            except Exception as e:
                print(f"Could not read {log_file}: {e}")
                continue
        
        if not zap_log_content:
            print("⚠️  Warning: Could not find ZAP scan logs. Checked locations:")
            for log_file in log_files[:6]:  # Show first 6 paths
                print(f"   - {log_file}")
        
        if zap_log_content:
            print(f"Parsing ZAP log content...")
            # Parse WARN-NEW and FAIL-NEW entries from ZAP log
            # Pattern: WARN-NEW: Alert Name [10001] x 11 (where x 11 is count)
            warn_pattern = re.compile(r'^WARN-NEW:\s+(.+?)\s+\[.*?\]\s+x\s+(\d+)', re.MULTILINE)
            fail_pattern = re.compile(r'^FAIL-NEW:\s+(.+?)\s+\[.*?\]\s+x\s+(\d+)', re.MULTILINE)
            
            found_alerts = {}
            
            # Extract warnings (treated as MEDIUM severity)
            warn_matches = warn_pattern.finditer(zap_log_content)
            warn_count = 0
            for match in warn_matches:
                alert_name = match.group(1).strip()
                count = int(match.group(2))
                if alert_name not in found_alerts:
                    found_alerts[alert_name] = {'severity': 'MEDIUM', 'count': 0}
                found_alerts[alert_name]['count'] += count
                warn_count += 1
            
            print(f"Found {warn_count} WARN-NEW entries")
            
            # Extract failures (treated as HIGH severity)
            fail_matches = fail_pattern.finditer(zap_log_content)
            fail_count = 0
            for match in fail_matches:
                alert_name = match.group(1).strip()
                count = int(match.group(2))
                if alert_name not in found_alerts:
                    found_alerts[alert_name] = {'severity': 'HIGH', 'count': 0}
                found_alerts[alert_name]['severity'] = 'HIGH'  # Override if also in warnings
                found_alerts[alert_name]['count'] += count
                fail_count += 1
            
            print(f"Found {fail_count} FAIL-NEW entries")
            print(f"Total unique alerts: {len(found_alerts)}")
            
            # Convert found alerts to list format
            for alert_name, alert_info in found_alerts.items():
                alerts.append({
                    'alert': alert_name,
                    'risk': alert_info['severity'],
                    'riskdesc': alert_info['severity'],
                    'desc': f"Found {alert_info['count']} instance(s) of {alert_name}",
                    'solution': 'Review and remediate the identified security issue',
                    'instances': [{'uri': 'N/A'}]
                })
            
            if alerts:
                print(f"✅ Successfully parsed {len(alerts)} alerts from ZAP logs")
    
    if alerts:
        summary['tools_used'].append('OWASP ZAP')
        summary['tool_summaries']['OWASP ZAP'] = {
            'total_alerts': len(alerts),
            'unique_alert_types': len(set(a.get('alert', '') for a in alerts))
        }
        
        for alert in alerts:
            instances = alert.get("instances", []) or []
            first = instances[0] if instances else {}
            risk_level = alert.get("riskdesc", alert.get("risk", "Medium"))
            
            # Parse risk level
            if isinstance(risk_level, str):
                risk_level = risk_level.split(" ")[0] if " " in risk_level else risk_level
            
            severity = risk_level.upper()
            if severity not in summary['vulnerabilities_by_severity']:
                # Map to closest severity
                if 'high' in risk_level.lower() or 'critical' in risk_level.lower():
                    severity = 'HIGH'
                elif 'medium' in risk_level.lower():
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
            
            alert_name = alert.get('alert', 'Unknown Alert')
            vuln_data = {
                'tool': 'OWASP ZAP',
                'type': alert_name,
                'severity': severity,
                'file': first.get('uri') or alert.get('url', 'N/A'),
                'line': None,
                'description': alert.get('desc') or alert.get('message', 'No description'),
                'remediation': alert.get('solution', ''),
                'cwe': f"CWE-{alert.get('cweid')}" if alert.get("cweid") else 'N/A',
                'url': first.get('uri') or alert.get('url'),
                'endpoint': first.get('uri', '').split('?')[0] if first.get('uri') else None,
            }
            summary['vulnerabilities'].append(vuln_data)
            summary['total_vulnerabilities'] += 1
            summary['vulnerabilities_by_severity'][severity] += 1
            
            # Count by type
            alert_type = vuln_data['type']
            summary['vulnerabilities_by_type'][alert_type] = summary['vulnerabilities_by_type'].get(alert_type, 0) + 1
    
    # Ensure reports directory exists
    os.makedirs(reports_dir, exist_ok=True)
    
    # Write summary report
    with open(f'{reports_dir}/dast-summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Write text summary
    with open(f'{reports_dir}/dast-summary.txt', 'w') as f:
        f.write("DAST Security Scan Summary Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Tools Used: {', '.join(summary['tools_used'])}\n")
        f.write(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}\n\n")
        
        f.write("Vulnerabilities by Severity:\n")
        for severity, count in summary['vulnerabilities_by_severity'].items():
            f.write(f"  {severity}: {count}\n")
        
        f.write("\nVulnerabilities by Type:\n")
        for alert_type, count in sorted(summary['vulnerabilities_by_type'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"  {alert_type}: {count}\n")
        
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
            f.write(f"URL: {vuln.get('url', 'N/A')}\n")
            f.write(f"Endpoint: {vuln.get('endpoint', 'N/A')}\n")
            f.write(f"CWE: {vuln['cwe']}\n")
            f.write(f"Description: {vuln['description']}\n")
            f.write(f"Remediation: {vuln.get('remediation', 'N/A')}\n")
            f.write("-" * 30 + "\n")
    
    print(f"DAST summary report generated with {summary['total_vulnerabilities']} vulnerabilities")
    return summary

if __name__ == "__main__":
    combine_dast_reports()

