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
    
    # Parse SAST report
    sast_file = 'reports/sast-report.json'
    if os.path.exists(sast_file):
        print(f"\nParsing SAST report: {sast_file}")
        sast_parser = SASTParser(sast_file)
        sast_vulns = sast_parser.parse()
        all_vulnerabilities.extend(sast_vulns)
        print(f"Found {len(sast_vulns)} vulnerabilities")
    
    # Parse SCA report - prefer summary, fallback to individual reports
    sca_summary_file = 'reports/sca-summary.json'
    sca_file = 'reports/sca-report.json'
    
    if os.path.exists(sca_summary_file):
        print(f"\nParsing SCA summary report: {sca_summary_file}")
        sca_parser = SCAParser(sca_summary_file)
        sca_vulns = sca_parser.parse()
        all_vulnerabilities.extend(sca_vulns)
        print(f"Found {len(sca_vulns)} vulnerabilities from SCA scan")
    elif os.path.exists(sca_file):
        print(f"\nParsing SCA report: {sca_file}")
        sca_parser = SCAParser(sca_file)
        sca_vulns = sca_parser.parse()
        all_vulnerabilities.extend(sca_vulns)
        print(f"Found {len(sca_vulns)} vulnerabilities")
    else:
        print("\nNo SCA reports found. Skipping SCA parsing.")
    
    # Parse DAST report
    dast_file = 'reports/dast-report.json'
    if os.path.exists(dast_file):
        print(f"\nParsing DAST report: {dast_file}")
        dast_parser = DASTParser(dast_file)
        dast_vulns = dast_parser.parse()
        all_vulnerabilities.extend(dast_vulns)
        print(f"Found {len(dast_vulns)} vulnerabilities")
    
    # Save unified report
    output_file = 'reports/unified-vulnerabilities.json'
    with open(output_file, 'w') as f:
        json.dump(all_vulnerabilities, f, indent=2)
    
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

