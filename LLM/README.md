# LLM Policy Generation Module

This module generates security policies from vulnerability findings using Large Language Models (LLMs). It supports multiple free models including Gemini, Groq, Hugging Face, and OpenRouter.ai models, and evaluates policy quality using BLEU and ROUGE-L metrics.

## Overview

The LLM module transforms unified vulnerability reports into structured security policies that align with:
- **ISO/IEC 27001** - Information Security Management Standard
- **NIST Cybersecurity Framework (CSF)** - Cybersecurity framework

## Directory Structure

```
LLM/
├── README.md                    # This file
├── Scripts/                     # LLM-related scripts
│   ├── generate_policies.py    # Main policy generation script
│   ├── evaluate_text_metrics.py # BLEU and ROUGE-L evaluation
│   ├── evaluate_structure.py    # Structure validation
│   ├── make_comparison_md.py    # Comparison report generator
│   ├── mappings.py             # CWE to ISO/NIST mappings
│   └── prompt_template.txt      # LLM prompt template
└── reports/                     # Generated outputs
    ├── policies_gemini.yaml     # Gemini-generated policies
    ├── policies_groq.yaml       # Groq-generated policies
    ├── policies_hf.yaml        # Hugging Face-generated policies
    ├── policies_openrouter_*.yaml # OpenRouter.ai-generated policies (multiple models)
    ├── eval_metrics.txt         # BLEU/ROUGE-L evaluation results
    ├── eval_structure.txt       # Structure validation results
    └── unified-vulnerabilities.json # Input file (copied from reports/)
```

## Prerequisites

1. **Python Dependencies**: Install from `requirements.txt`
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Variables**: Set up API keys
   ```bash
   # Create .env file or set environment variables
   # Google Gemini (FREE tier)
   export GEMINI_API_KEY="your_gemini_key"
   # Groq (FREE tier)
   export GROQ_API_KEY="your_groq_key"
   # Hugging Face (FREE tier)
   export HUGGINGFACEHUB_API_TOKEN="your_hf_token"
   # OpenRouter.ai (FREE tier - required for OpenRouter models)
   export OPENROUTER_API_KEY="your_openrouter_key"
   # Optional: specify HF model
   export HF_MODEL="meta-llama/Llama-3.1-8B-Instruct"
   ```

3. **Unified Vulnerability Report**: Run `parse_reports.py` first to generate `LLM/reports/unified-vulnerabilities.json`

## Usage

### Step 1: Generate Policies

Generate security policies from unified vulnerabilities:

```bash
python LLM/Scripts/generate_policies.py
```

This script:
1. Loads vulnerabilities from `LLM/reports/unified-vulnerabilities.json`
2. Groups vulnerabilities by theme (SQL Injection, XSS, etc.)
3. Generates policies using multiple free LLM APIs:
   - Google Gemini (FREE tier)
   - Groq (FREE tier)
   - Hugging Face (FREE tier)
   - OpenRouter.ai models (FREE tier):
     - DeepSeek V3 0324
     - Gemini 2.0 Flash Experimental
     - Llama 3.3 70B Instruct
     - GPT-OSS 20B
     - Nemotron Nano 12B 2 VL
     - Mistral 7B Instruct
4. Saves outputs to YAML files

**Outputs**:
- `LLM/reports/policies_gemini.yaml`
- `LLM/reports/policies_groq.yaml`
- `LLM/reports/policies_hf.yaml`
- `LLM/reports/policies_openrouter_*.yaml` (one file per OpenRouter model)

### Step 2: Evaluate Text Metrics

Evaluate policy quality using BLEU and ROUGE-L metrics:

```bash
python LLM/Scripts/evaluate_text_metrics.py
```

This script:
1. Loads both policy YAML files
2. Computes BLEU score (n-gram precision)
3. Computes ROUGE-L score (longest common subsequence)
4. Validates policy structure
5. Writes results to `LLM/reports/eval_metrics.txt`

**Output**: `LLM/reports/eval_metrics.txt`

### Step 3: Evaluate Structure

Validate structural compliance of policies:

```bash
python LLM/Scripts/evaluate_structure.py
```

This script:
1. Validates required fields (policy_id, title, mapping, etc.)
2. Checks ISO 27001 and NIST CSF control mappings
3. Computes statistics (controls per policy, unique mappings, etc.)
4. Writes results to `LLM/reports/eval_structure.txt`

**Output**: `LLM/reports/eval_structure.txt`

### Step 4: Generate Comparison Report

Create a markdown comparison report:

```bash
python LLM/Scripts/make_comparison_md.py
```

This script:
1. Reads evaluation metrics and structure results
2. Combines them into a markdown comparison report
3. Writes to `reports/llm_comparison.md`

**Output**: `reports/llm_comparison.md`

## Configuration

### API Keys

Set environment variables:

```bash
# Google Gemini (FREE tier)
export GEMINI_API_KEY="your_gemini_key"

# Groq (FREE tier)
export GROQ_API_KEY="your_groq_key"

# Hugging Face (FREE tier)
export HUGGINGFACEHUB_API_TOKEN="hf_..."
# or
export HF_TOKEN="hf_..."

# OpenRouter.ai (FREE tier - required for OpenRouter models)
export OPENROUTER_API_KEY="sk-or-..."

# Optional: Specify HF model
export HF_MODEL="microsoft/Phi-3-mini-4k-instruct"
```

Or create a `.env` file:

```
GEMINI_API_KEY=your_gemini_key
GROQ_API_KEY=your_groq_key
HUGGINGFACEHUB_API_TOKEN=hf_...
OPENROUTER_API_KEY=sk-or-...
HF_MODEL=meta-llama/Llama-3.1-8B-Instruct
```

### Model Providers

**Google Gemini**:
- Models: `gemini-1.5-flash`, `gemini-1.5-pro`
- Free tier available
- Get API key: https://makersuite.google.com/app/apikey

**Groq**:
- Models: `llama-3.1-70b-versatile`, `llama-3.1-8b-instant`, `mixtral-8x7b-32768`
- Free tier available
- Get API key: https://console.groq.com/

**Hugging Face**:
- Models: Various instruction-tuned models via Inference API
- Free tier available (limited access)
- Get API token: https://huggingface.co/settings/tokens

**OpenRouter.ai**:
- Free models available:
  - `deepseek/deepseek-v3-0324` - DeepSeek V3 0324
  - `google/gemini-2.0-flash-exp` - Gemini 2.0 Flash Experimental
  - `meta-llama/Llama-3.3-70B-Instruct` - Llama 3.3 70B Instruct
  - `gpt-oss/gpt-oss-20b` - GPT-OSS 20B
  - `nvidia/nemotron-nano-12b-2-vl` - Nemotron Nano 12B 2 VL
  - `mistralai/mistral-7b-instruct` - Mistral 7B Instruct
- 200 free requests per day
- Get API key: https://openrouter.ai/keys

## Policy Structure

Generated policies follow this YAML structure:

```yaml
policies:
  - policy_id: "POL-001"
    title: "Policy Title"
    description: "Policy description"
    mapping:
      iso27001:
        - "A.9.4.2"
        - "A.14.1.3"
      nist_csf:
        - "PR.AC-1"
        - "DE.CM-1"
    scope: "Systems/components this policy applies to"
    controls:
      - id: "CTRL-001"
        title: "Control Title"
        description: "Control description"
        implementation: "Implementation guidance"
    verification:
      - "Verification method 1"
      - "Verification method 2"
    owner: "Security Team"
    status: "draft"
    created_at: "2025-01-01"
    last_updated: "2025-01-01"
```

## Evaluation Metrics

### BLEU Score
- **Range**: 0-1 (higher is better)
- **Purpose**: Measures n-gram precision between generated and reference policies
- **Interpretation**: Higher scores indicate more similar policy content

### ROUGE-L Score
- **Range**: 0-1 (higher is better)
- **Purpose**: Measures longest common subsequence recall
- **Interpretation**: Higher scores indicate better fluency and content overlap

### Structure Validation
Checks for:
- Required fields presence
- Valid ISO 27001 control format (A.X.Y.Z)
- Valid NIST CSF control identifiers
- Control completeness
- Verification methods

## Troubleshooting

### Gemini API Errors
- **Error**: "GEMINI_API_KEY not set"
  - **Solution**: Set `GEMINI_API_KEY` or `GOOGLE_API_KEY` environment variable
- **Error**: "API rate limit exceeded"
  - **Solution**: Wait and retry, or check your API quota

### Groq API Errors
- **Error**: "GROQ_API_KEY not set"
  - **Solution**: Set `GROQ_API_KEY` environment variable
- **Error**: "API rate limit exceeded"
  - **Solution**: Wait and retry

### OpenRouter API Errors
- **Error**: "OPENROUTER_API_KEY not set"
  - **Solution**: Set `OPENROUTER_API_KEY` environment variable
- **Error**: "API rate limit exceeded" or "429"
  - **Solution**: You've exceeded the 200 free requests/day limit. Wait until reset or add credits
- **Error**: "Insufficient credits" or "402"
  - **Solution**: Free models should work without credits. Check model name or add credits if needed

### Hugging Face API Errors
- **Error**: "HUGGINGFACEHUB_API_TOKEN not set"
  - **Solution**: Set `HUGGINGFACEHUB_API_TOKEN` or `HF_TOKEN`
- **Error**: "Model not found"
  - **Solution**: Check model name or use fallback model
- **Error**: "Model requires authentication"
  - **Solution**: Ensure token has access to gated models

### Missing Dependencies
- **Error**: "sacrebleu not found"
  - **Solution**: `pip install sacrebleu`
- **Error**: "rouge-score not found"
  - **Solution**: `pip install rouge-score`
- **Error**: "nltk data not found"
  - **Solution**: Script auto-downloads, but can run `python -m nltk.downloader punkt`

### Empty Policies
- **Cause**: No vulnerabilities in unified report
- **Solution**: Ensure `parse_reports.py` found vulnerabilities, check security scans ran successfully

### YAML Parsing Errors
- **Cause**: LLM response not in valid YAML format
- **Solution**: Check model output, may need to adjust prompt or use different model

## Mappings

The `mappings.py` module provides:
- **CWE to Theme Mapping**: Maps CWE identifiers to vulnerability themes
- **Theme to ISO 27001 Mapping**: Maps themes to ISO 27001 control IDs
- **Theme to NIST CSF Mapping**: Maps themes to NIST CSF control identifiers
- **Suggested Controls**: Provides seed controls for LLM prompts

## Integration with Pipeline

The LLM module is integrated into the DevSecOps pipeline (`.github/workflows/devsecops.yml`):

1. **After report unification**: Unified vulnerabilities are available
2. **Policy generation**: `generate_policies.py` runs automatically
3. **Evaluation**: Both evaluation scripts run
4. **Comparison**: Comparison report is generated
5. **Artifacts**: All outputs are uploaded as artifacts

## References

- [ISO/IEC 27001 Standard](https://www.iso.org/standard/54534.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## License

This module is part of the AI-DevSecOps Project and follows the same license as the main project.

