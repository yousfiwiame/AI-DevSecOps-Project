# AI-DevSecOps Project: Automated Security Policy Generation

A Flask e-commerce application integrated with a complete DevSecOps pipeline that uses Large Language Models (LLMs) to automatically generate security policies from vulnerability reports. This project demonstrates the integration of SAST, SCA, and DAST security tools with AI-assisted policy generation conforming to NIST CSF and ISO/IEC 27001 standards.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Project Structure](#project-structure)
- [File Documentation](#file-documentation)
- [Getting Started](#getting-started)
- [DevSecOps Pipeline](#devsecops-pipeline)
- [Configuration](#configuration)
- [LLM Models Used](#-llm-models-used)
- [Evaluation Metrics](#evaluation-metrics)

## 🎯 Project Overview

This project implements a proof-of-concept DevSecOps pipeline that:

1. **Scans for vulnerabilities** using SAST (Static Application Security Testing), SCA (Software Composition Analysis), and DAST (Dynamic Application Security Testing) tools
2. **Parses and normalizes** security reports into a unified format
3. **Generates security policies** using LLMs (Gemini, Groq, Hugging Face, and OpenRouter models) based on detected vulnerabilities
4. **Evaluates policy quality** using BLEU and ROUGE-L metrics

The Flask application intentionally contains **25+ security vulnerabilities** for testing and demonstration purposes.

## 📁 Project Structure

```
AI-DevSecOps-Project-2/
├── app.py                          # Flask e-commerce application with intentional vulnerabilities
├── requirements.txt                # Python dependencies
├── README.md                       # This file - comprehensive project documentation
│
├── .github/
│   └── workflows/                  # GitHub Actions CI/CD workflows
│       └── devsecops.yml          # Unified DevSecOps pipeline (SAST, SCA, DAST, LLM generation)
│
├── parsers/                        # Vulnerability report parsers
│   ├── __init__.py               # Python package initialization
│   ├── base_parser.py            # Base parser class with normalization utilities
│   ├── sast_parser.py            # SAST report parser (SonarQube, can also handle Bandit)
│   ├── sca_parser.py             # SCA report parser (Dependency-Check, pip-audit, Safety)
│   └── dast_parser.py             # DAST report parser (OWASP ZAP)
│
├── scripts/                        # Utility scripts
│   ├── parse_reports.py          # Main script to unify all security reports
│   ├── validate_unified_report.py # Validates unified report against schema
│   ├── generate_sca_summary.py   # Generates SCA summary from multiple tools
│   ├── generate_sast_summary.py  # Generates SAST summary from SonarQube (and optionally Bandit)
│   └── generate_dast_summary.py  # Generates DAST summary from OWASP ZAP
│
├── schemas/                        # JSON schemas
│   └── unified_vulnerabilities.schema.json  # Schema for unified vulnerability format
│
├── LLM/                            # LLM policy generation module
│   ├── README.md                  # LLM module documentation
│   ├── Scripts/                  # LLM-related scripts
│   │   ├── generate_policies.py  # Generates policies using Gemini/Groq/HF/OpenRouter APIs
│   │   ├── evaluate_text_metrics.py  # Computes BLEU and ROUGE-L metrics
│   │   ├── evaluate_structure.py      # Validates policy structure compliance
│   │   ├── make_comparison_md.py      # Creates comparison report
│   │   ├── mappings.py                # CWE to ISO/NIST mappings
│   │   └── prompt_template.txt        # LLM prompt template
│   └── reports/                   # Generated policy files and evaluations
│       ├── policies_gemini.yaml  # Gemini-generated policies
│       ├── policies_groq.yaml    # Groq-generated policies
│       ├── policies_hf.yaml      # Hugging Face-generated policies
│       ├── policies_openrouter_*.yaml  # OpenRouter-generated policies
│       ├── unified-vulnerabilities.json  # Unified vulnerabilities (input for LLMs)
│       ├── unified-vulnerabilities.sample.json  # Sample unified report
│       ├── eval_metrics.txt      # BLEU/ROUGE-L evaluation results
│       └── eval_structure.txt    # Structure validation results
│
├── static/                         # Static web assets
│   ├── css/
│   │   └── style.css             # Application stylesheet
│   ├── images/                    # Product images
│   │   ├── chair.jpg
│   │   ├── coffee.jpg
│   │   ├── hero-image.png
│   │   ├── lamp.jpg
│   │   ├── laptop.jpg
│   │   └── mouse.jpg
│   └── js/
│       ├── dashboard.js           # Dashboard JavaScript
│       └── main.js                # Main application JavaScript
│
├── templates/                      # Flask HTML templates
│   ├── admin.html                 # Admin panel template
│   ├── base.html                  # Base template
│   ├── cart.html                  # Shopping cart template
│   ├── checkout.html              # Checkout template
│   ├── dashboard.html             # User dashboard template
│   ├── index.html                 # Homepage template
│   ├── login.html                 # Login page template
│   ├── order_success.html         # Order success template
│   ├── product_detail.html        # Product detail template
│   └── products.html              # Products listing template
│
└── reports/                        # Generated security reports (created at runtime)
    └── (various report files generated by security tools)
```

## 📄 File Documentation

### Root Level Files

#### `app.py`
**Purpose**: Main Flask e-commerce application with intentional security vulnerabilities for testing.

**Key Features**:
- User authentication (login/register) with weak password hashing (MD5)
- Product catalog with SQL injection vulnerabilities
- Shopping cart and checkout functionality
- Admin panel with authorization bypass
- File upload endpoint with path traversal
- Payment processing with sensitive data logging
- Multiple API endpoints with various vulnerabilities

**Vulnerabilities** (25+):
- VULN-1: Weak secret key
- VULN-2: Debug mode enabled
- VULN-3: No CSRF protection
- VULN-4: SQL Injection in login
- VULN-5: Weak password hashing (MD5)
- VULN-6: SQL Injection in search
- VULN-7: Session fixation
- VULN-8: No input validation
- VULN-9: Logging sensitive data
- VULN-10-26: Various other vulnerabilities (XSS, command injection, IDOR, etc.)

#### `requirements.txt`
**Purpose**: Python package dependencies for the entire project.

**Key Dependencies**:
- Flask 3.0.0 - Web framework
- transformers, torch - For Hugging Face LLM models
- google-generativeai - For Gemini API integration
- groq - For Groq API integration
- nltk, rouge-score, sacrebleu - For evaluation metrics
- beautifulsoup4, lxml - For report parsing
- pandas, matplotlib - For data visualization


### GitHub Workflows (`.github/workflows/`)

#### `devsecops.yml`
**Purpose**: Unified DevSecOps pipeline that runs all security scans and generates policies in a single workflow.

**What it does**:
1. **SAST (Static Application Security Testing)**:
   - Runs SonarCloud analysis using SonarCloud GitHub Action
   - Configures SonarCloud project using `sonar-project.properties`
   - Downloads SAST issues from SonarCloud API
   - Generates SAST summary report

2. **SCA (Software Composition Analysis)**:
   - Runs Snyk Python scan (if token available)
   - Runs Snyk Code scan
   - Runs OWASP Dependency-Check
   - Runs pip-audit
   - Runs Safety check
   - Runs Trivy filesystem scan
   - Generates SCA summary report
   - Uploads SARIF to GitHub Code Scanning

3. **DAST (Dynamic Application Security Testing)**:
   - Starts Flask application
   - Runs OWASP ZAP baseline scan
   - Runs OWASP ZAP full scan
   - Parses scan results
   - Generates DAST summary report

4. **Report Unification and Policy Generation**:
   - Generates summaries for SAST, SCA, and DAST
   - Normalizes report filenames
   - Unifies all reports into `unified-vulnerabilities.json`
   - Validates unified report
   - Generates policies with LLMs (Gemini, Groq, Hugging Face, OpenRouter)
   - Evaluates policies (BLEU, ROUGE-L metrics)
   - Creates comparison reports
   - Uploads all reports and policies as artifact

**Triggers**: 
- Push/PR to main/develop branches
- Manual trigger (`workflow_dispatch`)

**Benefits of Unified Approach**:
- **Simplicity**: Single workflow file, easier to understand and maintain
- **No artifact downloads**: All reports available directly in the same workflow
- **Complete visibility**: All scans and results visible in one workflow run
- **Sequential execution**: Ensures proper order of operations (SAST → SCA → DAST → Unify → LLM)

**Note**: SonarCloud (SonarQube Cloud) is used for SAST analysis. The SAST parser and summary generator can handle Bandit if its reports are added later, but the workflow currently only runs SonarCloud.

---

### Parsers (`parsers/`)

#### `__init__.py`
**Purpose**: Python package initialization file to make parsers a proper Python module.

#### `base_parser.py`
**Purpose**: Base parser class providing common normalization utilities for all parsers.

**Key Methods**:
- `normalize(item: dict) -> dict`: Normalizes vulnerability items to unified schema
- `_normalize_severity(severity: str) -> str`: Maps various severity formats to CRITICAL/HIGH/MEDIUM/LOW

**Usage**: All specific parsers (SAST, SCA, DAST) inherit from this class.

#### `sast_parser.py`
**Purpose**: Parses SAST (Static Application Security Testing) reports.

**Supports**:
- **SonarCloud**: Primary SAST tool used in this project (JSON format from SonarCloud API)
- **Bandit**: Python security linter reports (JSON format) - optional, not used in workflow

**Output**: List of normalized vulnerability dictionaries with fields:
- vulnerability, severity, cwe, file, line, description, tool

**Inherits from**: `BaseParser`

**Note**: The workflow currently only uses SonarCloud for SAST. The parser supports Bandit format for backwards compatibility or future expansion.

#### `sca_parser.py`
**Purpose**: Parses SCA (Software Composition Analysis) reports.

**Supports**:
- **OWASP Dependency-Check**: JSON and XML formats
- **SCA Summary**: Unified summary format from `generate_sca_summary.py`

**Output**: List of normalized dependency vulnerability dictionaries with fields:
- vulnerability, severity, cwe, file, description, remediation, cve, package, version, tool

**Inherits from**: `BaseParser`

#### `dast_parser.py`
**Purpose**: Parses DAST (Dynamic Application Security Testing) reports.

**Supports**:
- **OWASP ZAP**: JSON format (both "site" array and direct "alerts" formats)

**Output**: List of normalized vulnerability dictionaries with fields:
- vulnerability, severity, cwe, file, description, remediation, url, endpoint, tool

**Inherits from**: `BaseParser`

---

### Scripts (`scripts/`)

#### `parse_reports.py`
**Purpose**: Main script that unifies all security reports into a single JSON file.

**What it does**:
1. Parses SAST reports:
   - Prefers `sast-summary.json` (from `generate_sast_summary.py`)
   - Falls back to individual reports (`sonarqube-issues.json`, `bandit.json`)
   - Uses `SASTParser` for individual reports
2. Parses SCA summary report using `SCAParser`
3. Parses DAST report using `DASTParser`
4. Combines all findings into `reports/unified-vulnerabilities.json`
5. Copies unified report to `LLM/reports/unified-vulnerabilities.json` for LLM processing

**Note**: In the current setup, SAST only uses SonarCloud, but the parser can handle Bandit if its reports exist.

**Usage**:
```bash
python scripts/parse_reports.py
```

**Output**: 
- `reports/unified-vulnerabilities.json`
- `LLM/reports/unified-vulnerabilities.json`

#### `validate_unified_report.py`
**Purpose**: Validates the unified vulnerability report against the schema.

**What it does**:
- Checks that report is a JSON array
- Validates each item has required fields (severity, description, tool)
- Validates severity values (CRITICAL, HIGH, MEDIUM, LOW)
- Ensures each item has either "vulnerability" or "type" field

**Usage**:
```bash
python scripts/validate_unified_report.py
```

**Exit codes**:
- 0: Validation passed
- 1: Validation failed (prints errors)
- 2: File not found or invalid JSON

#### `generate_sca_summary.py`
**Purpose**: Combines multiple SCA tool reports into a unified summary.

**What it does**:
1. Loads reports from:
   - Snyk Python (`snyk-python-report.json`)
   - Snyk Code (`snyk-code-report.json`)
   - OWASP Dependency-Check (`dependency-check-report.json`)
   - pip-audit (`pip-audit-report.json`)
   - Safety (`safety-detailed-report.json`)
   - Trivy (`trivy.sarif`)
2. Normalizes all vulnerabilities to common format
3. Generates summary statistics
4. Writes `reports/sca-summary.json` and `reports/sca-summary.txt`

**Usage**:
```bash
python scripts/generate_sca_summary.py
```

**Output**:
- `reports/sca-summary.json` (structured JSON)
- `reports/sca-summary.txt` (human-readable text)

#### `generate_sast_summary.py`
**Purpose**: Combines multiple SAST tool reports into a unified summary.

**What it does**:
1. Loads reports from:
   - SonarCloud (`sonarqube-issues.json`) - primary tool used
   - Bandit (`bandit.json`) - optional, not used in current workflow
2. Normalizes all vulnerabilities to common format
3. Generates summary statistics
4. Writes `reports/sast-summary.json` and `reports/sast-summary.txt`

**Usage**:
```bash
python scripts/generate_sast_summary.py
```

**Output**:
- `reports/sast-summary.json` (structured JSON)
- `reports/sast-summary.txt` (human-readable text)

**Note**: Currently only SonarCloud is used, but the script can process Bandit reports if they exist.

---

### Schemas (`schemas/`)

#### `unified_vulnerabilities.schema.json`
**Purpose**: JSON Schema definition for the unified vulnerability format.

**Required Fields**:
- `severity`: One of CRITICAL, HIGH, MEDIUM, LOW
- `description`: String description
- `tool`: Tool that found the vulnerability
- Either `vulnerability` or `type`: Vulnerability name

**Optional Fields**:
- `cwe`: CWE identifier
- `file`: File path
- `line`: Line number
- `remediation`: Remediation guidance
- `cve`: CVE identifier
- `url`: URL/endpoint
- `package`, `version`: For dependency vulnerabilities

**Usage**: Referenced by validation script and LLM generation scripts.

---

### LLM Module (`LLM/`)

#### `LLM/README.md`
**Purpose**: Documentation for the LLM policy generation module.

**Contains**: Instructions for using LLM scripts, API key setup, troubleshooting.

#### `LLM/Scripts/generate_policies.py`
**Purpose**: Generates security policies using LLM APIs (Gemini, Groq, Hugging Face, and OpenRouter).

**What it does**:
1. Loads unified vulnerabilities from `LLM/reports/unified-vulnerabilities.json`
2. Groups vulnerabilities by theme (SQL Injection, XSS, etc.)
3. Builds prompt from template and grouped findings
4. Calls Gemini API to generate policies (FREE tier available)
5. Calls Groq API to generate policies (FREE tier available)
6. Calls Hugging Face API to generate policies
7. Calls OpenRouter API to generate policies (FREE tier models available)
8. Saves outputs as YAML files

**Environment Variables Required**:
- `GEMINI_API_KEY`: Google Gemini API key (FREE tier available)
- `GROQ_API_KEY`: Groq API key (FREE tier available)
- `HUGGINGFACEHUB_API_TOKEN` or `HF_TOKEN`: Hugging Face API token
- `OPENROUTER_API_KEY`: OpenRouter API key (FREE tier models available)

**Output**:
- `LLM/reports/policies_gemini.yaml`
- `LLM/reports/policies_groq.yaml`
- `LLM/reports/policies_hf.yaml`
- `LLM/reports/policies_openrouter_*.yaml` (multiple files for different models)

**Usage**:
```bash
python LLM/Scripts/generate_policies.py
```

#### `LLM/Scripts/evaluate_text_metrics.py`
**Purpose**: Computes BLEU and ROUGE-L metrics to evaluate policy quality.

**What it does**:
1. Loads generated policies from multiple models (Gemini, Groq, Hugging Face, OpenRouter)
2. Computes BLEU score (n-gram precision) comparing different model outputs
3. Computes ROUGE-L score (longest common subsequence)
4. Validates schema compliance
5. Writes evaluation results to `LLM/reports/eval_metrics.txt`

**Metrics Explained**:
- **BLEU**: Measures precision of generated text compared to reference
- **ROUGE-L**: Measures recall and fluency based on longest common subsequence

**Output**: `LLM/reports/eval_metrics.txt`

#### `LLM/Scripts/evaluate_structure.py`
**Purpose**: Validates structural compliance of generated policies.

**What it does**:
1. Loads both policy YAML files
2. Validates required fields:
   - policy_id, title, mapping (iso27001, nist_csf), scope, controls, verification, owner, status
3. Computes statistics (average controls per policy, ISO/NIST mappings, etc.)
4. Writes structure evaluation to `LLM/reports/eval_structure.txt`

**Output**: `LLM/reports/eval_structure.txt`

#### `LLM/Scripts/make_comparison_md.py`
**Purpose**: Generates a comparison report between different LLM-generated policies.

**What it does**:
1. Reads evaluation metrics and structure reports
2. Combines them into a markdown comparison report comparing all generated policies
3. Writes to `reports/llm_comparison.md`

**Output**: `reports/llm_comparison.md`

#### `LLM/Scripts/mappings.py`
**Purpose**: Defines mappings between CWE vulnerabilities and compliance frameworks.

**Key Mappings**:
- `CWE_THEME`: Maps CWE IDs to vulnerability themes (e.g., CWE-79 → XSS)
- `THEME_MAPPINGS`: Maps themes to ISO 27001 and NIST CSF controls
- `THEME_CONTROLS`: Suggested controls for each theme (seed for LLM prompts)

**Usage**: Used by `generate_policies.py` to group vulnerabilities and provide context.

#### `LLM/Scripts/prompt_template.txt`
**Purpose**: Template for LLM prompts that generate security policies.

**Structure**:
- System role: "You are a cybersecurity compliance assistant"
- User role: Instructions to produce YAML policies from grouped findings
- Rules: Required fields and structure for policies
- Placeholder: `{{GROUPED_JSON}}` - replaced with actual grouped vulnerabilities

**Usage**: Loaded and populated by `generate_policies.py`.

---

### Static Assets (`static/`)

#### `static/css/style.css`
**Purpose**: Stylesheet for the Flask e-commerce application.

#### `static/js/main.js`
**Purpose**: Main JavaScript for frontend functionality (cart, forms, etc.).

#### `static/js/dashboard.js`
**Purpose**: JavaScript for user dashboard functionality.

#### `static/images/*.jpg`, `static/images/*.png`
**Purpose**: Product images and hero image for the e-commerce site.

---

### Templates (`templates/`)

#### `templates/base.html`
**Purpose**: Base HTML template with common layout (navbar, footer).

#### `templates/index.html`
**Purpose**: Homepage template displaying featured products.

#### `templates/products.html`
**Purpose**: Products listing page with search and category filters.

#### `templates/product_detail.html`
**Purpose**: Individual product detail page.

#### `templates/cart.html`
**Purpose**: Shopping cart page.

#### `templates/checkout.html`
**Purpose**: Checkout page.

#### `templates/login.html`
**Purpose**: User login page.

#### `templates/register.html`
**Purpose**: User registration page.

#### `templates/dashboard.html`
**Purpose**: User dashboard showing orders and account info.

#### `templates/admin.html`
**Purpose**: Admin panel template (requires admin role).

#### `templates/order_success.html`
**Purpose**: Order confirmation page.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Git
- Docker (for DAST scans)
- GitHub account (for CI/CD)

### Installation

1. **Clone the repository**:
```bash
git clone <your-repo-url>
cd AI-DevSecOps-Project-2
```

2. **Install Python dependencies**:
```bash
pip install -r requirements.txt
# Optional: Install security tools for local testing
# pip install bandit pip-audit safety
```

3. **Set up environment variables** (create `.env` file):
```bash
GEMINI_API_KEY=your_gemini_key
GROQ_API_KEY=your_groq_key
HUGGINGFACEHUB_API_TOKEN=your_hf_token
OPENROUTER_API_KEY=your_openrouter_key
SNYK_TOKEN=your_snyk_token  # Optional
SONAR_TOKEN=your_sonar_token  # Required for SAST analysis
```

4. **Create required directories**:
```bash
mkdir -p reports LLM/reports
```

5. **Initialize the database**:
```bash
python app.py  # Creates ecommerce.db with sample data
```

### Running Locally

1. **Start the Flask application**:
```bash
python app.py
```
Application will be available at `http://localhost:5000`

2. **Run security scans manually**:
```bash
# SAST (SonarCloud - requires SonarCloud account and token)
# Note: SonarCloud analysis is configured via sonar-project.properties
# The workflow uses SonarCloud GitHub Action for automated analysis.
# For local testing, you can also use Bandit:
# bandit -r . -f json -o reports/bandit.json

# SCA
pip-audit -f json -o reports/pip-audit-report.json
safety check --full-report --json > reports/safety-detailed-report.json
python scripts/generate_sca_summary.py

# DAST (requires app running)
docker run --rm --network="host" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 \
  -J reports/dast-report.json

# Generate SAST summary (if you have SonarCloud report)
python scripts/generate_sast_summary.py
```

3. **Generate summaries**:
```bash
# Generate SAST summary (requires SonarCloud report or other SAST reports)
python scripts/generate_sast_summary.py

# Generate SCA summary
python scripts/generate_sca_summary.py
```

4. **Unify reports**:
```bash
python scripts/parse_reports.py
```

5. **Generate policies**:
```bash
python LLM/Scripts/generate_policies.py
```

6. **Evaluate policies**:
```bash
python LLM/Scripts/evaluate_text_metrics.py
python LLM/Scripts/evaluate_structure.py
python LLM/Scripts/make_comparison_md.py
```

---

## 🔄 DevSecOps Pipeline

### Pipeline Flow

```
Code Push/PR / Manual Trigger
    ↓
┌─────────────────────────────────────────────────┐
│  DevSecOps Pipeline (devsecops.yml)            │
├─────────────────────────────────────────────────┤
│  1. SAST Analysis                                │
│     - SonarCloud analysis                       │
│     - SonarCloud GitHub Action                  │
│     - Downloads SAST issues from SonarCloud API │
│     - Generates SAST summary                    │
│                                                  │
│  2. SCA Analysis                                │
│     - Snyk Python & Code scans                 │
│     - OWASP Dependency-Check                    │
│     - pip-audit, Safety                         │
│     - Trivy filesystem scan                     │
│     - Generates SCA summary                     │
│                                                  │
│  3. DAST Analysis                                │
│     - Start Flask application                   │
│     - OWASP ZAP Baseline scan                  │
│     - OWASP ZAP Full scan                       │
│     - Generates DAST summary                    │
│                                                  │
│  4. Report Unification                          │
│     - Generate all summaries                    │
│     - Normalize report filenames               │
│     - Parse all reports                         │
│     - Unify to single format                    │
│     - Validate schema                           │
│     - Create unified-vulnerabilities.json       │
│                                                  │
│  5. LLM Policy Generation                       │
│     - Google Gemini (gemini-2.0-flash-exp,     │
│       gemini-1.5-flash)                         │
│     - Groq (llama-3.3-70b, llama-3.1-70b)     │
│     - Hugging Face models                       │
│     - OpenRouter (free tier models)             │
│     - Generates policies_gemini.yaml           │
│     - Generates policies_groq.yaml             │
│     - Generates policies_hf.yaml               │
│     - Generates policies_openrouter_*.yaml     │
│                                                  │
│  6. Evaluation                                  │
│     - BLEU metrics                              │
│     - ROUGE-L metrics                           │
│     - Structure validation                      │
│     - Generates comparison report              │
│                                                  │
│  7. Artifact Upload                             │
│     - All unified reports                       │
│     - Generated policies                        │
│     - Evaluation results                        │
│     - Summary reports                           │
└─────────────────────────────────────────────────┘
```

### CI/CD Workflow

The project uses a **unified DevSecOps pipeline** that runs all security scans and policy generation in a single workflow:

**`devsecops.yml`**: Complete DevSecOps pipeline
- **SAST**: SonarCloud analysis using SonarCloud GitHub Action
- **SCA**: Multiple tools (Snyk, Dependency-Check, pip-audit, Safety, Trivy)
- **DAST**: OWASP ZAP baseline and full scans
- **Unification**: All reports combined into `unified-vulnerabilities.json`
- **Policy Generation**: LLM-based policy generation (Gemini, Groq, Hugging Face, OpenRouter)
- **Evaluation**: BLEU, ROUGE-L, and structural validation
- **Artifacts**: All reports, summaries, and policies uploaded as single artifact

**Architecture Benefits**: 
- **Simplicity**: Single workflow file, easier to understand and maintain
- **No artifact downloads**: All reports available directly in the same workflow
- **Complete visibility**: All scans and results visible in one workflow run
- **Sequential execution**: Ensures proper order of operations (SAST → SCA → DAST → Unify → LLM)

---

## ⚙️ Configuration

### GitHub Secrets

Set these secrets in your GitHub repository settings:

- `GEMINI_API_KEY`: Google Gemini API key for policy generation (FREE tier available)
- `GROQ_API_KEY`: Groq API key for policy generation (FREE tier available)
- `HUGGINGFACEHUB_API_TOKEN`: Hugging Face API token
- `OPENROUTER_API_KEY`: OpenRouter API key for policy generation (FREE tier models available)
- `SONAR_TOKEN`: SonarCloud authentication token (required for SAST analysis)
- `SNYK_TOKEN`: Snyk token for dependency scanning (optional)

### Local Configuration

Create a `.env` file in the project root:
```
GEMINI_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
HUGGINGFACEHUB_API_TOKEN=your_hf_token_here
OPENROUTER_API_KEY=your_openrouter_key_here
SONAR_TOKEN=your_sonar_token_here
SNYK_TOKEN=your_snyk_token_here  # Optional
```

---

## 🤖 LLM Models Used

The project uses multiple LLM providers to generate security policies, prioritizing free-tier models:

### Google Gemini
- **Models**: `gemini-2.0-flash-exp`, `gemini-1.5-flash`, `gemini-1.5-flash-latest`, `gemini-1.5-pro-latest`
- **API**: Google Generative AI
- **Cost**: FREE tier available
- **Output**: `policies_gemini.yaml`

### Groq
- **Models**: `llama-3.3-70b-versatile`, `llama-3.1-70b-versatile`, `llama-3.1-8b-instant`, `mixtral-8x7b-32768`
- **API**: Groq API
- **Cost**: FREE tier available
- **Output**: `policies_groq.yaml`

### Hugging Face
- **Models**: `HuggingFaceH4/zephyr-7b-beta`, `mistralai/Mistral-7B-Instruct-v0.2`, `microsoft/Phi-3-mini-4k-instruct`, `meta-llama/Llama-2-7b-chat-hf`
- **API**: Hugging Face Inference API
- **Cost**: FREE (may require access approval for some models)
- **Output**: `policies_hf.yaml`

### OpenRouter
- **Models**: Multiple free-tier models including:
  - `meta-llama/llama-3.1-8b-instruct:free`
  - `meta-llama/llama-3.2-3b-instruct:free`
  - `mistralai/mistral-7b-instruct:free`
  - `huggingfaceh4/zephyr-7b-beta:free`
  - `google/gemini-flash-1.5`
  - And more
- **API**: OpenRouter API
- **Cost**: FREE tier models available
- **Output**: `policies_openrouter_*.yaml` (multiple files, one per model)

**Note**: The script tries models in priority order (Gemini → Groq → Hugging Face → OpenRouter) and uses the first successful generation. Multiple models can be used simultaneously for comparative analysis.

---

## 📊 Evaluation Metrics

### BLEU (Bilingual Evaluation Understudy)

Measures precision of generated text:
- Range: 0-100 (higher is better)
- Compares n-grams between generated and reference policies

### ROUGE-L (Recall-Oriented Understudy for Gisting - Longest)

Measures recall and fluency:
- Range: 0-1 (higher is better)
- Based on longest common subsequence
- Considers both directions (reference→candidate and candidate→reference)

### Structure Validation

Checks for:
- Required fields (policy_id, title, mapping, scope, controls, etc.)
- ISO 27001 control mappings
- NIST CSF control mappings
- Policy completeness

---

## 🔍 Troubleshooting

### DAST Workflow Fails

- Ensure Flask app starts successfully
- Check Docker is available in GitHub Actions
- Verify app is accessible on `http://localhost:5000`

### LLM Generation Fails

- Verify API keys are set correctly
- Check API quotas and rate limits
- Ensure `unified-vulnerabilities.json` exists

### Parsing Errors

- Verify report files exist in `reports/` directory
- Check report formats match expected structure
- Run validation script to identify issues

---

## 📝 Notes

- **Intentional Vulnerabilities**: The Flask app contains vulnerabilities for testing purposes. **DO NOT** deploy this application to production!

- **Workflow Architecture**: The project uses a unified `devsecops.yml` workflow that runs all security scans (SAST, SCA, DAST) sequentially and then generates policies using LLMs. See the [DevSecOps Pipeline](#-devsecops-pipeline) section for details.

- **API Costs**: LLM generation uses external APIs. Most models used (Gemini, Groq, OpenRouter free tier) are available at no cost, but monitor usage for rate limits.

---

## 📚 References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001](https://www.iso.org/standard/54534.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [SonarCloud](https://sonarcloud.io/) - Primary SAST tool used in this project (SonarQube Cloud)
- [Bandit](https://bandit.readthedocs.io/) - Optional SAST tool (parser supports it for local testing)

---

## 📄 License

This project is for educational purposes. See LICENSE file for details.

---

**Last Updated**: 2025
**Project Version**: 1.0
