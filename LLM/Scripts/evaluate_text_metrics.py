#!/usr/bin/env python3
"""
Evaluate generated security policies using BLEU and ROUGE-L metrics.
This script compares OpenAI and Hugging Face generated policies.
"""
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any

try:
    from sacrebleu import BLEU
    BLEU_AVAILABLE = True
except ImportError:
    BLEU_AVAILABLE = False
    print("Warning: sacrebleu package not available. BLEU metrics will be skipped.")

try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    ROUGE_AVAILABLE = False
    print("Warning: rouge-score package not available. ROUGE-L metrics will be skipped.")

import nltk
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)


def load_policies(file_path: Path) -> Dict[str, Any]:
    """Load policies from YAML file"""
    if not file_path.exists():
        print(f"Warning: {file_path} not found")
        return {}
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def extract_text_from_policies(policies: Dict[str, Any]) -> str:
    """Extract text content from policies for evaluation"""
    text_parts = []
    
    if 'policies' in policies:
        for policy in policies['policies']:
            # Extract key text fields
            text_parts.append(policy.get('title', ''))
            text_parts.append(policy.get('description', ''))
            text_parts.append(policy.get('scope', ''))
            
            # Extract control descriptions
            for control in policy.get('controls', []):
                text_parts.append(control.get('title', ''))
                text_parts.append(control.get('description', ''))
                text_parts.append(control.get('implementation', ''))
            
            # Extract verification methods
            for verification in policy.get('verification', []):
                text_parts.append(str(verification))
    
    return ' '.join(text_parts)


def tokenize_text(text: str) -> List[str]:
    """Tokenize text into sentences and words"""
    sentences = nltk.sent_tokenize(text)
    words = []
    for sentence in sentences:
        words.extend(nltk.word_tokenize(sentence.lower()))
    return words


def calculate_bleu(reference: str, candidate: str) -> float:
    """Calculate BLEU score"""
    if not BLEU_AVAILABLE:
        return 0.0
    
    try:
        # BLEU expects list of references and candidates
        bleu = BLEU()
        score = bleu.sentence_score(candidate, [reference])
        return score.score / 100.0  # Normalize to 0-1
    except Exception as e:
        print(f"Warning: BLEU calculation failed: {e}")
        return 0.0


def calculate_rouge_l(reference: str, candidate: str) -> float:
    """Calculate ROUGE-L score"""
    if not ROUGE_AVAILABLE:
        return 0.0
    
    try:
        scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
        scores = scorer.score(reference, candidate)
        return scores['rougeL'].fmeasure
    except Exception as e:
        print(f"Warning: ROUGE-L calculation failed: {e}")
        return 0.0


def validate_policy_structure(policies: Dict[str, Any]) -> Dict[str, Any]:
    """Validate policy structure and return statistics"""
    validation = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "statistics": {}
    }
    
    if 'policies' not in policies:
        validation["valid"] = False
        validation["errors"].append("Missing 'policies' key")
        return validation
    
    policy_list = policies['policies']
    if not isinstance(policy_list, list):
        validation["valid"] = False
        validation["errors"].append("'policies' must be a list")
        return validation
    
    required_fields = ['policy_id', 'title', 'mapping', 'scope', 'controls', 'verification', 'owner', 'status']
    
    valid_policies = 0
    total_controls = 0
    iso_mappings = set()
    nist_mappings = set()
    
    for idx, policy in enumerate(policy_list):
        # Check required fields
        for field in required_fields:
            if field not in policy:
                validation["warnings"].append(f"Policy {idx}: Missing field '{field}'")
        
        # Validate mapping structure
        if 'mapping' in policy:
            mapping = policy['mapping']
            if 'iso27001' in mapping:
                iso_mappings.update(mapping['iso27001'])
            if 'nist_csf' in mapping:
                nist_mappings.update(mapping['nist_csf'])
        
        # Count controls
        if 'controls' in policy:
            total_controls += len(policy['controls'])
        
        valid_policies += 1
    
    validation["statistics"] = {
        "total_policies": len(policy_list),
        "valid_policies": valid_policies,
        "total_controls": total_controls,
        "avg_controls_per_policy": total_controls / valid_policies if valid_policies > 0 else 0,
        "unique_iso27001_controls": len(iso_mappings),
        "unique_nist_csf_controls": len(nist_mappings),
    }
    
    return validation


def main():
    """Main evaluation function"""
    print("=" * 60)
    print("Policy Evaluation: BLEU and ROUGE-L Metrics")
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
    
    # Extract text for evaluation - create a dictionary for easier access
    print("\n📊 Extracting text for evaluation...")
    model_texts = {}
    for name, policies in available_models:
        text = extract_text_from_policies(policies)
        model_texts[name] = text
        if text:
            print(f"   {name} text length: {len(text)} characters")
    
    # Calculate metrics - compare available models
    results = {
        "comparisons": {},
        "validations": {},
    }
    
    # Compare available models (use first model as reference if multiple)
    reference_text = None
    reference_name = None
    
    # Find first available model as reference (priority: Gemini, Groq, Hugging Face, then OpenRouter)
    for name in ["Gemini", "Groq", "Hugging Face"]:
        if name in model_texts and model_texts[name]:
            reference_text = model_texts[name]
            reference_name = name
            break
    
    # If no standard model, use first OpenRouter model
    if not reference_text:
        for name in model_texts:
            if name.startswith("OpenRouter:") and model_texts[name]:
                reference_text = model_texts[name]
                reference_name = name
                break
    
    if reference_text and len(available_models) > 1:
        print(f"\n📈 Calculating BLEU and ROUGE-L scores (using {reference_name} as reference)...")
        for name, _ in available_models:
            if name == reference_name:
                continue
            candidate_text = model_texts.get(name, "")
            
            if candidate_text:
                bleu = calculate_bleu(reference_text, candidate_text)
                rouge = calculate_rouge_l(reference_text, candidate_text)
                results["comparisons"][name] = {
                    "bleu": bleu,
                    "rouge_l": rouge
                }
                print(f"   {reference_name} vs {name}:")
                print(f"      BLEU Score: {bleu:.4f}")
                print(f"      ROUGE-L Score: {rouge:.4f}")
    else:
        print("\n⚠️  Skipping text metrics (need at least 2 models for comparison)")
    
    # Validate structure for all available models
    print("\n🔍 Validating policy structure...")
    for name, policies in available_models:
        results["validations"][name] = validate_policy_structure(policies)
        print(f"   {name} policies: {results['validations'][name]['statistics']}")
    
    # Write results
    output_file = reports_dir / "eval_metrics.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("Policy Evaluation Metrics\n")
        f.write("=" * 60 + "\n\n")
        
        if results["comparisons"]:
            f.write("Text Similarity Metrics\n")
            f.write("-" * 60 + "\n")
            for name, metrics in results["comparisons"].items():
                f.write(f"{reference_name} vs {name}:\n")
                f.write(f"  BLEU Score: {metrics['bleu']:.4f}\n")
                f.write(f"    (Range: 0-1, higher is better)\n")
                f.write(f"    Measures n-gram precision between policies\n\n")
                f.write(f"  ROUGE-L Score: {metrics['rouge_l']:.4f}\n")
                f.write(f"    (Range: 0-1, higher is better)\n")
                f.write(f"    Measures longest common subsequence recall\n\n")
        else:
            f.write("Text Similarity Metrics: Not available (need at least 2 models)\n\n")
        
        f.write("Policy Structure Validation\n")
        f.write("-" * 60 + "\n")
        
        for name, validation in results["validations"].items():
            f.write(f"\n{name} Policies:\n")
            stats = validation['statistics']
            f.write(f"  Total Policies: {stats['total_policies']}\n")
            f.write(f"  Valid Policies: {stats['valid_policies']}\n")
            f.write(f"  Total Controls: {stats['total_controls']}\n")
            f.write(f"  Avg Controls/Policy: {stats['avg_controls_per_policy']:.2f}\n")
            f.write(f"  Unique ISO 27001 Controls: {stats['unique_iso27001_controls']}\n")
            f.write(f"  Unique NIST CSF Controls: {stats['unique_nist_csf_controls']}\n")
            
            if validation.get('warnings'):
                f.write("\n  Warnings:\n")
                for warning in validation['warnings'][:10]:
                    f.write(f"    - {warning}\n")
        
        f.write("\n" + "=" * 60 + "\n")
    
    print(f"\n✅ Evaluation results saved to: {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()

