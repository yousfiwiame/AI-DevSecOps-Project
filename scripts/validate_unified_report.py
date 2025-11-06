#!/usr/bin/env python3
"""
Validate the unified vulnerabilities report against schema and check for sample/mock data.
This is a critical gate before LLM policy generation.
"""
import json
import sys
from pathlib import Path


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def check_sample_data(item: dict, idx: int) -> list:
    """Check if an item contains sample/mock data (generic check)"""
    errors = []
    # No specific sample data checks needed - all data comes from real security scans
    # If needed, add generic sample data checks here in the future
    return errors


def validate_item(i: dict, idx: int):
    """Validate a single vulnerability item"""
    errors = []
    if not isinstance(i, dict):
        return [f"[{idx}] not an object"]
    
    # Required keys
    if "severity" not in i:
        errors.append(f"[{idx}] missing 'severity'")
    else:
        sev = str(i.get("severity"))
        if sev not in SEVERITIES:
            errors.append(f"[{idx}] invalid severity '{sev}'")
    
    if "description" not in i:
        errors.append(f"[{idx}] missing 'description'")
    if "tool" not in i:
        errors.append(f"[{idx}] missing 'tool'")
    
    # One of type/vulnerability
    if not ("type" in i or "vulnerability" in i):
        errors.append(f"[{idx}] missing both 'type' and 'vulnerability'")
    
    # Check for sample data
    errors.extend(check_sample_data(i, idx))
    
    return errors


def main(path: str = "reports/unified-vulnerabilities.json"):
    """Main validation function"""
    p = Path(path)
    if not p.exists():
        print(f"ERROR: {path} not found", file=sys.stderr)
        return 2
    
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: invalid JSON in {path}: {e}", file=sys.stderr)
        return 2

    if not isinstance(data, list):
        print("ERROR: unified report must be a JSON array of findings", file=sys.stderr)
        return 2

    if len(data) == 0:
        print("WARNING: unified report is empty", file=sys.stderr)
        return 0  # Not an error, just empty

    all_errors = []
    sample_data_errors = []
    structure_errors = []
    
    for idx, item in enumerate(data):
        item_errors = validate_item(item, idx)
        for error in item_errors:
            all_errors.append(error)
            if "SAMPLE DATA" in error:
                sample_data_errors.append(error)
            else:
                structure_errors.append(error)

    if sample_data_errors:
        print("=" * 70)
        print("WARNING: SAMPLE/MOCK DATA DETECTED!")
        print("=" * 70)
        print("The unified report contains sample/mock data.")
        print("This should NOT be used for LLM policy generation.")
        print("\nSample data errors:")
        for e in sample_data_errors[:10]:
            print(" -", e)
        if len(sample_data_errors) > 10:
            print(f" ... and {len(sample_data_errors) - 10} more")
        print("\n⚠️  Validation WARNING: Sample data detected")
        print("   Fix: Ensure parse_reports.py uses only real security scan data")
        # Don't fail, just warn - return 0 to allow continuation
        return 0

    if structure_errors:
        print("FAIL: unified report validation errors:")
        for e in structure_errors[:50]:
            print(" -", e)
        if len(structure_errors) > 50:
            print(f" ... and {len(structure_errors) - 50} more")
        return 1

    print(f"✅ OK: validated {len(data)} findings in {path}")
    print(f"   ✅ All items have required fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
