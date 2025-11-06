#!/usr/bin/env python3
"""
Validate structural compliance of generated security policies.
This script checks that policies conform to required structure and mappings.
"""
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any


def load_policies(file_path: Path) -> Dict[str, Any]:
    """Load policies from YAML file"""
    if not file_path.exists():
        print(f"Warning: {file_path} not found")
        return {}
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def validate_policy(policy: Dict[str, Any], idx: int) -> Dict[str, Any]:
    """Validate a single policy"""
    validation = {
        "valid": True,
        "errors": [],
        "warnings": [],
    }
    
    required_fields = {
        'policy_id': 'Policy ID',
        'title': 'Title',
        'mapping': 'ISO/NIST Mappings',
        'scope': 'Scope',
        'controls': 'Controls',
        'verification': 'Verification',
        'owner': 'Owner',
        'status': 'Status',
    }
    
    # Check required fields
    for field, name in required_fields.items():
        if field not in policy:
            validation["valid"] = False
            validation["errors"].append(f"Missing required field: {name} ({field})")
    
    # Validate mapping structure
    if 'mapping' in policy:
        mapping = policy['mapping']
        if not isinstance(mapping, dict):
            validation["valid"] = False
            validation["errors"].append("'mapping' must be a dictionary")
        else:
            if 'iso27001' not in mapping:
                validation["warnings"].append("Missing ISO 27001 mappings")
            elif not isinstance(mapping['iso27001'], list):
                validation["warnings"].append("ISO 27001 mappings must be a list")
            
            if 'nist_csf' not in mapping:
                validation["warnings"].append("Missing NIST CSF mappings")
            elif not isinstance(mapping['nist_csf'], list):
                validation["warnings"].append("NIST CSF mappings must be a list")
    
    # Validate controls
    if 'controls' in policy:
        controls = policy['controls']
        if not isinstance(controls, list):
            validation["warnings"].append("'controls' must be a list")
        elif len(controls) == 0:
            validation["warnings"].append("No controls defined")
        else:
            for ctrl_idx, control in enumerate(controls):
                if not isinstance(control, dict):
                    validation["warnings"].append(f"Control {ctrl_idx} is not a dictionary")
                else:
                    if 'title' not in control:
                        validation["warnings"].append(f"Control {ctrl_idx} missing title")
                    if 'description' not in control:
                        validation["warnings"].append(f"Control {ctrl_idx} missing description")
    
    # Validate verification
    if 'verification' in policy:
        verification = policy['verification']
        if not isinstance(verification, list):
            validation["warnings"].append("'verification' must be a list")
        elif len(verification) == 0:
            validation["warnings"].append("No verification methods defined")
    
    return validation


def validate_all_policies(policies: Dict[str, Any]) -> Dict[str, Any]:
    """Validate all policies and compute statistics"""
    results = {
        "total_policies": 0,
        "valid_policies": 0,
        "invalid_policies": 0,
        "total_controls": 0,
        "total_verification_methods": 0,
        "iso27001_controls": set(),
        "nist_csf_controls": set(),
        "errors": [],
        "warnings": [],
        "policy_details": [],
    }
    
    if 'policies' not in policies:
        results["errors"].append("Missing 'policies' key in YAML")
        return results
    
    policy_list = policies['policies']
    if not isinstance(policy_list, list):
        results["errors"].append("'policies' must be a list")
        return results
    
    results["total_policies"] = len(policy_list)
    
    for idx, policy in enumerate(policy_list):
        validation = validate_policy(policy, idx)
        policy_detail = {
            "index": idx,
            "policy_id": policy.get('policy_id', f'POL-{idx+1:03d}'),
            "valid": validation["valid"],
            "errors": validation["errors"],
            "warnings": validation["warnings"],
        }
        
        if validation["valid"]:
            results["valid_policies"] += 1
        else:
            results["invalid_policies"] += 1
        
        results["errors"].extend([f"Policy {idx}: {e}" for e in validation["errors"]])
        results["warnings"].extend([f"Policy {idx}: {w}" for w in validation["warnings"]])
        
        # Collect statistics
        if 'controls' in policy:
            controls = policy['controls']
            if isinstance(controls, list):
                results["total_controls"] += len(controls)
        
        if 'verification' in policy:
            verification = policy['verification']
            if isinstance(verification, list):
                results["total_verification_methods"] += len(verification)
        
        if 'mapping' in policy:
            mapping = policy['mapping']
            if isinstance(mapping, dict):
                if 'iso27001' in mapping and isinstance(mapping['iso27001'], list):
                    results["iso27001_controls"].update(mapping['iso27001'])
                if 'nist_csf' in mapping and isinstance(mapping['nist_csf'], list):
                    results["nist_csf_controls"].update(mapping['nist_csf'])
        
        results["policy_details"].append(policy_detail)
    
    return results


def main():
    """Main validation function"""
    print("=" * 60)
    print("Policy Structure Validation")
    print("=" * 60)
    
    reports_dir = Path(__file__).parent.parent / "reports"
    
    # Load policies - dynamically find all policy files
    print("\n📥 Loading policies...")
    
    # Standard model files
    gemini_file = reports_dir / "policies_gemini.yaml"
    groq_file = reports_dir / "policies_groq.yaml"
    hf_file = reports_dir / "policies_hf.yaml"
    
    # Find all OpenRouter policy files
    openrouter_files = list(reports_dir.glob("policies_openrouter_*.yaml"))
    
    # Load policies
    available_models = []
    
    if gemini_file.exists():
        gemini_policies = load_policies(gemini_file)
        if gemini_policies:
            available_models.append(("Gemini", gemini_policies))
    
    if groq_file.exists():
        groq_policies = load_policies(groq_file)
        if groq_policies:
            available_models.append(("Groq", groq_policies))
    
    if hf_file.exists():
        hf_policies = load_policies(hf_file)
        if hf_policies:
            available_models.append(("Hugging Face", hf_policies))
    
    # Load OpenRouter policies
    for openrouter_file in openrouter_files:
        model_name = openrouter_file.stem.replace("policies_openrouter_", "").replace("_", " ").title()
        openrouter_policies = load_policies(openrouter_file)
        if openrouter_policies:
            available_models.append((f"OpenRouter: {model_name}", openrouter_policies))
    
    if not available_models:
        print(f"❌ No policies found!")
        print(f"   Checked: {gemini_file}, {groq_file}, {hf_file}, and OpenRouter files")
        print("   Run generate_policies.py first")
        sys.exit(1)
    
    print(f"   Found policies from: {', '.join([name for name, _ in available_models])}")
    
    # Validate all available policies
    results = {}
    for name, policies in available_models:
        print(f"\n🔍 Validating {name} policies...")
        results[name] = validate_all_policies(policies)
    
    # Print results for all models
    for name, result in results.items():
        print(f"\n{name} Policies:")
        print(f"   Total Policies: {result['total_policies']}")
        print(f"   Valid Policies: {result['valid_policies']}")
        print(f"   Invalid Policies: {result['invalid_policies']}")
        print(f"   Total Controls: {result['total_controls']}")
        print(f"   Avg Controls/Policy: {result['total_controls'] / result['total_policies'] if result['total_policies'] > 0 else 0:.2f}")
        print(f"   Unique ISO 27001 Controls: {len(result['iso27001_controls'])}")
        print(f"   Unique NIST CSF Controls: {len(result['nist_csf_controls'])}")
        
        if result['errors']:
            print(f"\n   ❌ Errors: {len(result['errors'])}")
            for error in result['errors'][:5]:
                print(f"      - {error}")
        
        if result['warnings']:
            print(f"\n   ⚠️  Warnings: {len(result['warnings'])}")
            for warning in result['warnings'][:5]:
                print(f"      - {warning}")
    
    # Write results
    output_file = reports_dir / "eval_structure.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("Policy Structure Validation Results\n")
        f.write("=" * 60 + "\n\n")
        
        for name, result in results.items():
            f.write(f"{name} Policies\n")
            f.write("-" * 60 + "\n")
            f.write(f"Total Policies: {result['total_policies']}\n")
            f.write(f"Valid Policies: {result['valid_policies']}\n")
            f.write(f"Invalid Policies: {result['invalid_policies']}\n")
            f.write(f"Total Controls: {result['total_controls']}\n")
            f.write(f"Average Controls per Policy: {result['total_controls'] / result['total_policies'] if result['total_policies'] > 0 else 0:.2f}\n")
            f.write(f"Total Verification Methods: {result['total_verification_methods']}\n")
            f.write(f"Unique ISO 27001 Controls: {len(result['iso27001_controls'])}\n")
            if result['iso27001_controls']:
                f.write(f"  ISO Controls: {', '.join(sorted(result['iso27001_controls']))}\n")
            f.write(f"Unique NIST CSF Controls: {len(result['nist_csf_controls'])}\n")
            if result['nist_csf_controls']:
                f.write(f"  NIST Controls: {', '.join(sorted(result['nist_csf_controls']))}\n")
            
            if result['errors']:
                f.write(f"\nErrors ({len(result['errors'])}):\n")
                for error in result['errors']:
                    f.write(f"  - {error}\n")
            
            if result['warnings']:
                f.write(f"\nWarnings ({len(result['warnings'])}):\n")
                for warning in result['warnings']:
                    f.write(f"  - {warning}\n")
            
            f.write("\n" + "=" * 60 + "\n")
    
    print(f"\n✅ Validation results saved to: {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()

