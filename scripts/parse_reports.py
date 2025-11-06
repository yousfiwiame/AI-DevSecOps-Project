"""
Parse all security reports and generate unified vulnerability list
"""
import sys
import json
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from parsers.sast_parser import SASTParser
from parsers.sca_parser import SCAParser
from parsers.dast_parser import DASTParser

def main():
    print("=" * 60)
    print("Security Report Parser")
    print("=" * 60)
    
    all_vulnerabilities = []
    
    # Parse SAST reports - prefer summary, fallback to individual reports
    sast_summary_file = 'reports/sast-summary.json'
    bandit_file = 'reports/bandit.json'
    semgrep_file = 'reports/semgrep.json'
    sonarqube_file = 'reports/sonarqube-issues.json'
    
    combined_sast = 0
    if os.path.exists(sast_summary_file):
        print(f"\nParsing SAST summary report: {sast_summary_file}")
        summary_data = None
        try:
            with open(sast_summary_file, 'r', encoding='utf-8') as f:
                summary_data = json.load(f)
        except Exception as e:
            print(f"Error loading SAST summary: {e}")
        
        if summary_data and 'vulnerabilities' in summary_data:
            # SAST summary has vulnerabilities in unified format
            for vuln in summary_data['vulnerabilities']:
                # Ensure it's in the normalized format
                normalized = {
                    'vulnerability': vuln.get('type', vuln.get('vulnerability', 'Unknown')),
                    'severity': vuln.get('severity', 'MEDIUM'),
                    'cwe': vuln.get('cwe', 'N/A'),
                    'file': vuln.get('file', 'N/A'),
                    'line': vuln.get('line'),
                    'description': vuln.get('description', ''),
                    'tool': vuln.get('tool', 'Unknown'),
                }
                all_vulnerabilities.append(normalized)
                combined_sast += 1
            print(f"Found {combined_sast} SAST vulnerabilities from summary (all tools)")
    else:
        # Fallback to individual reports
        if os.path.exists(bandit_file):
            print(f"\nParsing SAST report: {bandit_file}")
            sast_parser = SASTParser(bandit_file)
            bandit_vulns = sast_parser.parse()
            all_vulnerabilities.extend(bandit_vulns)
            combined_sast += len(bandit_vulns)
        if os.path.exists(semgrep_file):
            print(f"\nParsing SAST report: {semgrep_file}")
            sast_parser = SASTParser(semgrep_file)
            semgrep_vulns = sast_parser.parse()
            all_vulnerabilities.extend(semgrep_vulns)
            combined_sast += len(semgrep_vulns)
        if os.path.exists(sonarqube_file):
            print(f"\nParsing SAST report: {sonarqube_file}")
            # SonarQube format might need special handling
            try:
                with open(sonarqube_file, 'r', encoding='utf-8') as f:
                    sonar_data = json.load(f)
                    issues = sonar_data.get('issues', [])
                    for issue in issues:
                        normalized = {
                            'vulnerability': issue.get('rule', 'Unknown'),
                            'severity': issue.get('severity', 'MEDIUM').upper(),
                            'cwe': 'N/A',
                            'file': issue.get('component', 'N/A'),
                            'line': issue.get('line'),
                            'description': issue.get('message', ''),
                            'tool': 'SonarQube',
                        }
                        all_vulnerabilities.append(normalized)
                        combined_sast += 1
            except Exception as e:
                print(f"Error parsing SonarQube report: {e}")
        
        if combined_sast:
            tools_used = []
            if os.path.exists(bandit_file):
                tools_used.append("Bandit")
            if os.path.exists(semgrep_file):
                tools_used.append("Semgrep")
            if os.path.exists(sonarqube_file):
                tools_used.append("SonarQube")
            tools_str = "+".join(tools_used) if tools_used else "SonarQube"
            print(f"Found {combined_sast} SAST vulnerabilities ({tools_str})")
    
    # Parse SCA report - prefer summary, fallback to individual reports
    sca_summary_file = 'reports/sca-summary.json'
    sca_file = 'reports/sca-report.json'
    
    combined_sca = 0
    if os.path.exists(sca_summary_file):
        print(f"\nParsing SCA summary report: {sca_summary_file}")
        try:
            # Check if summary has vulnerabilities
            with open(sca_summary_file, 'r', encoding='utf-8') as f:
                summary_data = json.load(f)
            
            print(f"SCA summary loaded. Keys: {list(summary_data.keys())}")
            vuln_count = len(summary_data.get('vulnerabilities', []))
            print(f"Vulnerabilities in summary: {vuln_count}")
            
            if summary_data and 'vulnerabilities' in summary_data and len(summary_data['vulnerabilities']) > 0:
                # Use SCAParser to parse summary
                print(f"Using SCAParser to parse summary...")
                sca_parser = SCAParser(sca_summary_file)
                sca_vulns = sca_parser.parse()
                print(f"SCAParser returned {len(sca_vulns)} vulnerabilities")
                if sca_vulns:
                    all_vulnerabilities.extend(sca_vulns)
                    combined_sca = len(sca_vulns)
                    print(f"✅ Found {combined_sca} vulnerabilities from SCA summary")
                else:
                    print(f"⚠️  SCAParser returned empty list despite summary having {vuln_count} vulnerabilities")
                    print(f"⚠️  Attempting direct parsing...")
                    # Fallback: parse directly from summary using BaseParser normalization
                    from parsers.base_parser import BaseParser
                    base_parser = BaseParser("")
                    for vuln in summary_data['vulnerabilities']:
                        normalized = {
                            'vulnerability': vuln.get('type', 'Dependency Vulnerability'),
                            'severity': vuln.get('severity', 'MEDIUM'),
                            'cwe': vuln.get('cwe', 'N/A'),
                            'file': vuln.get('file', 'requirements.txt'),
                            'line': vuln.get('line', 'N/A'),
                            'description': vuln.get('description', 'No description'),
                            'remediation': f"Update {vuln.get('package', 'dependency')} to version {vuln.get('fix_versions', ['latest'])[0] if vuln.get('fix_versions') else 'latest'}",
                            'cve': vuln.get('cve', 'N/A'),
                            'package': vuln.get('package', 'Unknown'),
                            'version': vuln.get('version', 'Unknown'),
                            'tool': vuln.get('tool', 'Unknown')
                        }
                        # Use normalize to ensure proper formatting
                        normalized_vuln = base_parser.normalize(normalized)
                        all_vulnerabilities.append(normalized_vuln)
                        combined_sca += 1
                    print(f"✅ Found {combined_sca} vulnerabilities via direct parsing")
            else:
                print(f"SCA summary exists but contains 0 vulnerabilities")
                print(f"Tools used: {summary_data.get('tools_used', [])}")
        except Exception as e:
            print(f"Error parsing SCA summary: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to individual reports
            if os.path.exists(sca_file):
                print(f"Falling back to individual SCA report: {sca_file}")
                sca_parser = SCAParser(sca_file)
                sca_vulns = sca_parser.parse()
                all_vulnerabilities.extend(sca_vulns)
                combined_sca = len(sca_vulns)
                print(f"Found {combined_sca} vulnerabilities from individual SCA report")
    elif os.path.exists(sca_file):
        print(f"\nParsing SCA report: {sca_file}")
        sca_parser = SCAParser(sca_file)
        sca_vulns = sca_parser.parse()
        all_vulnerabilities.extend(sca_vulns)
        combined_sca = len(sca_vulns)
        print(f"Found {combined_sca} vulnerabilities")
    else:
        print("\nNo SCA reports found. Skipping SCA parsing.")
    
    # Parse DAST report - prefer summary, fallback to individual report
    dast_summary_file = 'reports/dast-summary.json'
    dast_file = 'reports/dast-report.json'
    
    combined_dast = 0
    if os.path.exists(dast_summary_file):
        print(f"\nParsing DAST summary report: {dast_summary_file}")
        summary_data = None
        try:
            with open(dast_summary_file, 'r', encoding='utf-8') as f:
                summary_data = json.load(f)
        except Exception as e:
            print(f"Error loading DAST summary: {e}")
        
        if summary_data and 'vulnerabilities' in summary_data:
            # DAST summary has vulnerabilities in unified format
            vuln_list = summary_data['vulnerabilities']
            if isinstance(vuln_list, list) and len(vuln_list) > 0:
                from parsers.base_parser import BaseParser
                base_parser = BaseParser("")
                for vuln in vuln_list:
                    # Ensure it's in the normalized format
                    normalized = {
                        'vulnerability': vuln.get('type', vuln.get('vulnerability', 'Unknown')),
                        'severity': vuln.get('severity', 'MEDIUM'),
                        'cwe': vuln.get('cwe', 'N/A'),
                        'file': vuln.get('file', vuln.get('url', 'N/A')),
                        'line': vuln.get('line'),
                        'description': vuln.get('description', ''),
                        'remediation': vuln.get('remediation', ''),
                        'url': vuln.get('url'),
                        'endpoint': vuln.get('endpoint'),
                        'tool': vuln.get('tool', 'Unknown'),
                    }
                    # Use normalize to ensure proper formatting
                    normalized_vuln = base_parser.normalize(normalized)
                    all_vulnerabilities.append(normalized_vuln)
                    combined_dast += 1
                print(f"✅ Found {combined_dast} DAST vulnerabilities from summary")
            else:
                print(f"⚠️  DAST summary exists but vulnerabilities list is empty or invalid")
        else:
            print(f"⚠️  DAST summary exists but 'vulnerabilities' key not found or summary_data is None")
    elif os.path.exists(dast_file):
        print(f"\nParsing DAST report: {dast_file}")
        dast_parser = DASTParser(dast_file)
        dast_vulns = dast_parser.parse()
        all_vulnerabilities.extend(dast_vulns)
        combined_dast = len(dast_vulns)
        print(f"Found {combined_dast} DAST vulnerabilities")
    else:
        print("\nNo DAST reports found. Skipping DAST parsing.")
    
    # Print summary before saving
    print("\n" + "=" * 60)
    print("Parsing Summary")
    print("=" * 60)
    print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
    print(f"  - SAST: {combined_sast}")
    print(f"  - SCA: {combined_sca}")
    print(f"  - DAST: {combined_dast}")
    
    # Save unified report - always create the file, even if empty
    output_file = 'reports/unified-vulnerabilities.json'
    try:
        # Ensure reports directory exists
        os.makedirs('reports', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_vulnerabilities, f, indent=2)
        print(f"\n✅ Unified report saved to: {output_file}")
        print(f"   File size: {os.path.getsize(output_file)} bytes")
        print(f"   Vulnerability count: {len(all_vulnerabilities)}")
    except Exception as e:
        print(f"\n❌ Error saving unified report: {e}")
        import traceback
        traceback.print_exc()
        # Create empty file as fallback
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        print(f"⚠️  Created empty unified report as fallback")

    # Check if we have findings
    if len(all_vulnerabilities) == 0:
        print("\n⚠️  WARNING: No vulnerabilities found in any reports!")
        print("⚠️  This might indicate:")
        print("   - Reports were not downloaded correctly")
        print("   - Reports are empty")
        print("   - Summary scripts failed")
        print("⚠️  Keeping unified report empty - no sample data will be used")
    else:
        print(f"✅ Unified report contains {len(all_vulnerabilities)} real findings from security scans")
    
    # Also copy to LLM input location if available
    try:
        os.makedirs('LLM/reports', exist_ok=True)
        llm_output_file = 'LLM/reports/unified-vulnerabilities.json'
        with open(llm_output_file, 'w', encoding='utf-8') as lf:
            json.dump(all_vulnerabilities, lf, indent=2)
        print(f"✅ Also copied unified report to: {llm_output_file}")
        
        # Note: Only real parsed data is used, no sample files
    except Exception as e:
        print(f"❌ Error copying to LLM/reports: {e}")
        import traceback
        traceback.print_exc()

    print(f"\n{'=' * 60}")
    print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
    print(f"Unified report saved to: {output_file}")
    print("=" * 60)
    
    # Print summary
    high_count = len([v for v in all_vulnerabilities if v['severity'] == 'HIGH'])
    medium_count = len([v for v in all_vulnerabilities if v['severity'] == 'MEDIUM'])
    
    print(f"\nSeverity Breakdown:")
    print(f"  HIGH: {high_count}")
    print(f"  MEDIUM: {medium_count}")
    print(f"  LOW: {len(all_vulnerabilities) - high_count - medium_count}")

if __name__ == "__main__":
    main()