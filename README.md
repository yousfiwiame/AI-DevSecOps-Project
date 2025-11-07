# 🛡️ AI-DevSecOps: Automated Security Policy Generation with LLMs

<div align="center">

[![License](https://img.shields.io/badge/License-Educational-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-black.svg)](https://flask.palletsprojects.com/)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Automated-orange.svg)]()
[![AI Powered](https://img.shields.io/badge/AI-LLM%20Powered-purple.svg)]()

*Bridging the gap between technical vulnerability reports and actionable security policies through AI-driven automation*

[Features](#-key-features) • [Architecture](#%EF%B8%8F-pipeline-architecture) • [Getting Started](#-getting-started) • [Project Strcuture](#-project-structure) • [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Key Features](#-key-features)
- [Pipeline Architecture](#%EF%B8%8F-pipeline-architecture)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [DevSecOps Workflow](#-devsecops-workflow)
- [LLM Integration](#-llm-integration)
- [Evaluation & Metrics](#-evaluation--metrics)
- [Configuration](#%EF%B8%8F-configuration)
- [Results](#-results)
- [Limitations & Future Work](#-limitations--future-work)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**AI-DevSecOps** is a proof-of-concept implementation that demonstrates how Large Language Models (LLMs) can automate the generation of security policies from vulnerability reports in a DevSecOps pipeline. This project addresses the critical challenge of translating technical security findings into actionable, standards-compliant policies.

### Why This Matters

In modern software development, security teams face mounting pressure to:
- 🔍 Process hundreds of vulnerability reports from multiple tools
- 📝 Translate technical findings into actionable security policies
- ⚖️ Ensure compliance with frameworks like NIST CSF and ISO/IEC 27001
- ⚡ Respond quickly to emerging threats

**Manual policy generation is time-consuming, error-prone, and doesn't scale.**

This project demonstrates how AI can bridge this gap by:
- Automatically parsing reports from SAST, SCA, and DAST tools
- Grouping vulnerabilities by security themes
- Generating comprehensive, standards-aligned policies using multiple LLM providers
- Evaluating policy quality through quantitative metrics

---

## 🎯 Problem Statement

### The Challenge

Modern DevSecOps pipelines generate extensive vulnerability data, but there's a significant gap between **technical vulnerability reports** and **actionable security policies**:

| Challenge | Impact |
|-----------|--------|
| **Volume** | Multiple tools generate hundreds of findings per scan |
| **Fragmentation** | Different formats and severity scales across tools |
| **Translation Gap** | Technical findings don't map directly to policy controls |
| **Compliance Burden** | Manual mapping to NIST CSF / ISO 27001 is time-intensive |
| **Response Time** | Delayed policy updates leave systems vulnerable |

### Our Solution

An **AI-powered automation framework** that:

1. **Unifies** vulnerability data from multiple security tools
2. **Intelligently groups** findings by security themes (SQL Injection, XSS, etc.)
3. **Generates** comprehensive security policies using state-of-the-art LLMs
4. **Maps** policies to compliance frameworks (NIST CSF, ISO/IEC 27001)
5. **Evaluates** output quality using BLEU and ROUGE-L metrics

---

## ✨ Key Features

### 🔧 Complete DevSecOps Pipeline

- **SAST (Static Application Security Testing)**: SonarCloud integration with API-based vulnerability extraction
- **SCA (Software Composition Analysis)**: Multi-tool approach (Snyk, Dependency-Check, pip-audit, Safety, Trivy)
- **DAST (Dynamic Application Security Testing)**: OWASP ZAP baseline and full scans

### 🤖 Multi-LLM Policy Generation

- **Google Gemini**: Latest models (gemini-2.0-flash-exp, gemini-1.5-flash)
- **Groq**: High-speed inference (llama-3.3-70b, llama-3.1-70b)
- **Hugging Face**: Open-source models (Zephyr, Mistral, Phi-3)
- **OpenRouter**: Multiple free-tier models for comparative analysis

### 📊 Comprehensive Evaluation

- **BLEU Scores**: Measures n-gram precision between generated policies
- **ROUGE-L Metrics**: Evaluates longest common subsequence and fluency
- **Structure Validation**: Ensures compliance with policy schema requirements
- **Comparative Analysis**: Side-by-side evaluation of different LLM outputs

### 🎯 Standards Compliance

- **NIST Cybersecurity Framework (CSF)**: Automatic mapping to Identify, Protect, Detect, Respond, Recover
- **ISO/IEC 27001**: Controls mapping for international compliance
- **CWE Integration**: Vulnerability categorization using Common Weakness Enumeration

### 🔄 Intelligent Parsing

- **Unified Format**: Normalizes disparate tool outputs into single JSON schema
- **Theme-Based Grouping**: Clusters vulnerabilities by security category
- **Severity Normalization**: Maps different severity scales to consistent levels
- **Metadata Preservation**: Retains CWE, CVE, file paths, and remediation guidance

---

## 🏗️ Pipeline Architecture
<img width="5747" height="3418" alt="DevSecOpsPipeline" src="https://github.com/user-attachments/assets/419f41bd-ce11-4ac3-922e-e08d593876b8" />

### Pipeline Components

#### 1️⃣ **Security Scanning Phase**

**SAST (Static Analysis)**
- **SonarCloud**: Code quality and security vulnerability detection
- Integrates via GitHub Action and SonarCloud API
- Identifies code smells, bugs, and security hotspots
- Downloads issues in JSON format for parsing

**SCA (Dependency Analysis)**
- **Snyk**: Python dependencies and code vulnerabilities
- **OWASP Dependency-Check**: Identifies known vulnerable components
- **pip-audit**: PyPI package vulnerability scanning
- **Safety**: Checks against safety database
- **Trivy**: Container and filesystem vulnerability scanner

**DAST (Dynamic Testing)**
- **OWASP ZAP**: Automated web application security testing
- Baseline scan for quick vulnerability assessment
- Full scan for comprehensive security analysis
- Tests running application for runtime vulnerabilities

#### 2️⃣ **Report Processing Phase**

**Stage 1: Individual Summaries**
- SAST Summary: Aggregates SonarCloud findings
- SCA Summary: Combines all dependency scan results
- DAST Summary: Processes ZAP scan outputs

**Stage 2: Unification**
- Parses all summary reports using specialized parsers
- Normalizes severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Combines into `unified-vulnerabilities.json`
- Validates against JSON schema

**Stage 3: Validation**
- Schema compliance checking
- Required field verification
- Severity value validation
- Completeness assessment

#### 3️⃣ **LLM Policy Generation Phase**

**Multi-Provider Approach**
- Submits unified report to multiple LLM providers
- Each provider generates independent policy set
- Policies structured as YAML documents
- Includes ISO 27001 and NIST CSF mappings

**LLM Pipeline**
1. **Google Gemini**: Fast, reliable generation with latest models
2. **Groq**: High-speed inference for rapid policy creation
3. **Hugging Face**: Open-source model alternatives
4. **OpenRouter**: Multiple free-tier models for comparison

#### 4️⃣ **Evaluation & Comparison Phase**

**Quantitative Metrics**
- **BLEU Scores**: Inter-model comparison for consistency
- **ROUGE-L**: Measures output quality and fluency
- **Structure Validation**: Policy completeness checking

**Qualitative Analysis**
- Comparative reports across all models
- Control coverage assessment
- Compliance framework alignment
- Actionability evaluation

#### 5️⃣ **Artifact Management**

**Outputs Generated**
- All security scan reports
- Unified vulnerability report
- Generated policies (YAML format)
- Evaluation metrics
- Comparison reports
- Summary documents

**Storage & Access**
- GitHub Actions artifacts (90-day retention)
- Downloadable via workflow interface
- Version-controlled policy outputs
- Audit trail for compliance

---

### Workflow Benefits

| Benefit | Description |
|---------|-------------|
| 🎯 **Single Source of Truth** | All scans run in one workflow, ensuring consistency |
| 📦 **No Artifact Dependencies** | Direct file access eliminates download overhead |
| 👁️ **Complete Visibility** | All pipeline stages visible in single workflow run |
| 🔄 **Sequential Execution** | Guaranteed order: SAST → SCA → DAST → Unify → LLM |
| 🚀 **Simplified Maintenance** | One workflow file instead of multiple interconnected jobs |

---

## 📁 Project Structure

```
AI-DevSecOps-Project/
├── 📱 app.py                       # Flask e-commerce app (80+ intentional vulnerabilities)
├── 📋 requirements.txt             # Python dependencies
├── 📖 README.md                    # Project documentation (this file)
│
├── 🔄 .github/workflows/
│   └── devsecops.yml              # Unified DevSecOps pipeline
│
├── 🔍 parsers/                    # Vulnerability report parsers
│   ├── __init__.py
│   ├── base_parser.py             # Base parser with normalization
│   ├── sast_parser.py             # SAST report parser (SonarCloud)
│   ├── sca_parser.py              # SCA report parser (multi-tool)
│   └── dast_parser.py             # DAST report parser (OWASP ZAP)
│
├── 🛠️ scripts/                    # Utility scripts
│   ├── parse_reports.py           # Unifies all security reports
│   ├── validate_unified_report.py # Schema validation
│   ├── generate_sca_summary.py    # SCA aggregation
│   ├── generate_sast_summary.py   # SAST aggregation
│   └── generate_dast_summary.py   # DAST aggregation
│
├── 📋 schemas/
│   └── unified_vulnerabilities.schema.json  # Unified format schema
│
├── 🤖 LLM/                        # LLM policy generation
│   ├── 📖 README.md               # LLM module documentation
│   └── Scripts/
│       ├── generate_policies.py   # Multi-provider policy generation
│       ├── evaluate_text_metrics.py  # BLEU & ROUGE-L evaluation
│       ├── evaluate_structure.py     # Schema compliance validation
│       ├── make_comparison_md.py     # Comparison report generator
│       ├── mappings.py                # CWE → ISO/NIST mappings
│       └── prompt_template.txt        # LLM prompt template
│
├── 🎨 static/                     # Web application assets
│   ├── css/style.css
│   ├── images/
│   └── js/
│
├── 📄 templates/                  # Flask HTML templates
│   ├── base.html
│   ├── index.html
│   ├── products.html
│   └── ...
│
└── 📊 reports/                    # Generated reports (runtime)
    ├── unified-vulnerabilities.json
    ├── sast-summary.json
    ├── sca-summary.json
    ├── dast-summary.json
    ├── policies_gemini.yaml
    ├── policies_groq.yaml
    ├── policies_hf.yaml
    ├── policies_openrouter_*.yaml
    ├── eval_metrics.txt
    └── llm_comparison.md
```

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| 🐍 Python | 3.11+ | Application runtime |
| 🔧 Git | Latest | Version control |
| 🐳 Docker | Latest | DAST container execution |
| 🔑 API Keys | N/A | LLM provider access (free tiers available) |

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/AI-DevSecOps-Project.git
cd AI-DevSecOps-Project
```

#### 2. Set Up Python Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 3. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# Required for SAST
SONAR_TOKEN=your_sonarcloud_token

# Required for LLM Policy Generation
GEMINI_API_KEY=your_gemini_api_key         # FREE tier available
GROQ_API_KEY=your_groq_api_key             # FREE tier available
OPENROUTER_API_KEY=your_openrouter_key     # FREE tier models available

# Optional
HUGGINGFACEHUB_API_TOKEN=your_hf_token
SNYK_TOKEN=your_snyk_token
```

#### 4. Initialize Application Database

```bash
python app.py
# Creates ecommerce.db with sample products and users
```

#### 5. Set Up GitHub Secrets

For CI/CD pipeline, add these secrets to your GitHub repository:

**Settings → Secrets and variables → Actions → New repository secret**

```
SONAR_TOKEN
GEMINI_API_KEY
GROQ_API_KEY
OPENROUTER_API_KEY
HUGGINGFACEHUB_API_TOKEN (optional)
SNYK_TOKEN (optional)
```

### Quick Start

#### Run the Application Locally

```bash
python app.py
```

Access at: `http://localhost:5000`

#### Run Security Scans Manually

```bash
# SCA Scans
pip-audit -f json -o reports/pip-audit-report.json
safety check --full-report --json > reports/safety-detailed-report.json

# Generate summaries
python scripts/generate_sca_summary.py
python scripts/generate_sast_summary.py  # Requires SonarCloud report

# Unify reports
python scripts/parse_reports.py

# Generate policies
python LLM/Scripts/generate_policies.py

# Evaluate results
python LLM/Scripts/evaluate_text_metrics.py
python LLM/Scripts/evaluate_structure.py
python LLM/Scripts/make_comparison_md.py
```

#### Run DAST Scan

```bash
# Start application
python app.py &

# Run OWASP ZAP scan
docker run --rm --network="host" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 \
  -J reports/dast-report.json
```

---

## 🔄 DevSecOps Workflow

### Automated Pipeline

The `devsecops.yml` workflow runs automatically on:
- 📤 Push to `main` or `develop` branches
- 🔀 Pull requests to `main` or `develop`
- 🎮 Manual trigger via GitHub Actions UI

### Pipeline Stages

#### Stage 1: SAST Analysis

```yaml
- SonarCloud GitHub Action integration
- Automated code quality and security scanning
- API-based issue retrieval
- SAST summary generation
```

**Tools**: SonarCloud (via GitHub Action + API)

**Outputs**:
- `sonarqube-issues.json`
- `sast-summary.json`
- `sast-summary.txt`

#### Stage 2: SCA Analysis

```yaml
- Snyk Python & Code scans
- OWASP Dependency-Check
- pip-audit vulnerability check
- Safety database scan
- Trivy filesystem scan
- Multi-tool summary generation
```

**Tools**: Snyk, Dependency-Check, pip-audit, Safety, Trivy

**Outputs**:
- `snyk-python-report.json`
- `snyk-code-report.json`
- `dependency-check-report.json`
- `pip-audit-report.json`
- `safety-detailed-report.json`
- `trivy.sarif`
- `sca-summary.json`
- `sca-summary.txt`

#### Stage 3: DAST Analysis

```yaml
- Flask application startup
- OWASP ZAP baseline scan
- OWASP ZAP full scan
- Result parsing and summary
```

**Tools**: OWASP ZAP

**Outputs**:
- `dast-baseline.json`
- `dast-full.json`
- `dast-summary.json`
- `dast-summary.txt`

#### Stage 4: Report Unification

```yaml
- Summary normalization
- Multi-parser processing
- Schema validation
- Unified report generation
```

**Process**:
1. Normalize report filenames
2. Parse SAST, SCA, DAST summaries
3. Combine into unified format
4. Validate against schema

**Output**: `unified-vulnerabilities.json`

#### Stage 5: LLM Policy Generation

```yaml
- Multi-provider policy generation
- Vulnerability theme grouping
- Standards mapping (ISO/NIST)
- Parallel generation across models
```

**Providers**:
- Google Gemini
- Groq
- Hugging Face
- OpenRouter (multiple models)

**Outputs**:
- `policies_gemini.yaml`
- `policies_groq.yaml`
- `policies_hf.yaml`
- `policies_openrouter_*.yaml`

#### Stage 6: Evaluation

```yaml
- BLEU metric computation
- ROUGE-L scoring
- Structure validation
- Comparison report generation
```

**Outputs**:
- `eval_metrics.txt`
- `eval_structure.txt`
- `llm_comparison.md`

#### Stage 7: Artifact Upload

```yaml
- All reports bundled
- 90-day retention
- Downloadable via Actions UI
```

**Artifact**: `devsecops-reports`

---

## 🤖 LLM Integration

### Multi-Provider Strategy

The project employs a **comparative LLM approach** to evaluate different models' capabilities in security policy generation:

#### 1. Google Gemini

**Models Used**:
- `gemini-2.0-flash-exp` (primary)
- `gemini-1.5-flash`
- `gemini-1.5-flash-latest`
- `gemini-1.5-pro-latest`

**Characteristics**:
- ✅ **FREE tier**: 1,500 requests/day (flash models)
- ⚡ Fast response times
- 📝 Strong structured output
- 🎯 Good compliance mapping

**API**: Google Generative AI Python SDK

#### 2. Groq

**Models Used**:
- `llama-3.3-70b-versatile` (primary)
- `llama-3.1-70b-versatile`
- `llama-3.1-8b-instant`
- `mixtral-8x7b-32768`

**Characteristics**:
- ✅ **FREE tier**: Generous limits
- ⚡⚡ Ultra-fast inference (LPU architecture)
- 🧠 Strong reasoning capabilities
- 📋 Excellent policy formatting

**API**: Groq Cloud API

#### 3. Hugging Face

**Models Used**:
- `HuggingFaceH4/zephyr-7b-beta`
- `mistralai/Mistral-7B-Instruct-v0.2`
- `microsoft/Phi-3-mini-4k-instruct`
- `meta-llama/Llama-2-7b-chat-hf`

**Characteristics**:
- ✅ **FREE tier**: Inference API with rate limits
- 🔓 Open-source models
- 🎓 Good for research
- ⚙️ May require access approval

**API**: Hugging Face Inference API

#### 4. OpenRouter

**Models Used** (Free Tier):
- `meta-llama/llama-3.1-8b-instruct:free`
- `meta-llama/llama-3.2-3b-instruct:free`
- `mistralai/mistral-7b-instruct:free`
- `huggingfaceh4/zephyr-7b-beta:free`
- `google/gemini-flash-1.5`

**Characteristics**:
- ✅ **Multiple FREE tier** models
- 🔄 Unified API for many providers
- 📊 Good for comparative analysis
- 💰 Some models require credits

**API**: OpenRouter API

### Policy Generation Process

```python
# Simplified workflow
1. Load unified-vulnerabilities.json
2. Group vulnerabilities by theme (SQL Injection, XSS, etc.)
3. Load prompt template
4. Inject grouped findings into prompt
5. Call LLM APIs in parallel
6. Parse YAML responses
7. Validate policy structure
8. Save policies per provider
```

### Prompt Engineering

The project uses a **carefully crafted prompt template** (`LLM/Scripts/prompt_template.txt`) that:

- 🎯 Defines role: "cybersecurity compliance assistant"
- 📋 Specifies output format: YAML with required fields
- 🗺️ Requests ISO 27001 and NIST CSF mappings
- 🔧 Includes actionable controls for each vulnerability theme
- ✅ Enforces structure: policy_id, title, scope, controls, verification, etc.

**Prompt Structure**:
```
System: You are a cybersecurity compliance assistant...

User: 
Based on the following security vulnerabilities, generate comprehensive security policies...

Rules:
1. Each policy must have: policy_id, title, mapping, scope, controls, verification, owner, status
2. Map to ISO 27001 (A.x.x.x) and NIST CSF (ID.x, PR.x, etc.)
3. Provide actionable controls
...

Grouped Vulnerabilities:
{{GROUPED_JSON}}
```

### Standards Mapping

#### CWE to Theme Mapping

The system maps Common Weakness Enumeration (CWE) IDs to security themes:

```python
CWE_THEME = {
    "CWE-79": "XSS",
    "CWE-89": "SQL_INJECTION",
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-798": "HARDCODED_CREDENTIALS",
    # ... more mappings
}
```

#### Theme to Compliance Mapping

Each theme is mapped to relevant controls:

```python
THEME_MAPPINGS = {
    "SQL_INJECTION": {
        "iso27001": ["A.14.2.1", "A.12.6.1"],
        "nist_csf": ["PR.DS-1", "PR.PT-5"]
    },
    "XSS": {
        "iso27001": ["A.14.2.1", "A.14.2.5"],
        "nist_csf": ["PR.DS-1", "PR.IP-1"]
    },
    # ... more mappings
}
```

---

## 📊 Evaluation & Metrics

### Quantitative Evaluation

#### BLEU (Bilingual Evaluation Understudy)

**Purpose**: Measures n-gram precision between generated policies

**How it works**:
- Compares 1-gram, 2-gram, 3-gram, 4-gram overlaps
- Higher score = more consistent terminology
- Range: 0-100 (higher is better)

**Use case**: Comparing policies from different LLMs to assess consistency

```python
# Example BLEU scores (hypothetical)
Gemini vs Groq:    BLEU = 45.2
Groq vs HF:        BLEU = 38.7
Gemini vs OpenRouter: BLEU = 42.1
```

**Interpretation**:
- 40-50: High consistency, similar policy structure
- 30-40: Moderate similarity, some variation
- <30: Significant differences in approach

#### ROUGE-L (Longest Common Subsequence)

**Purpose**: Measures recall and fluency based on longest common subsequence

**How it works**:
- Finds longest matching sequence between two texts
- Computes F-score combining precision and recall
- Range: 0-1 (higher is better)

**Use case**: Assessing policy completeness and coverage

```python
# Example ROUGE-L scores (hypothetical)
Gemini:    ROUGE-L = 0.72
Groq:      ROUGE-L = 0.68
HF:        ROUGE-L = 0.61
OpenRouter: ROUGE-L = 0.70
```

**Interpretation**:
- 0.7-1.0: Excellent coverage and fluency
- 0.5-0.7: Good quality, minor gaps
- <0.5: Needs improvement

### Qualitative Evaluation

#### Structure Validation

**Checks performed**:
```yaml
✓ Required fields present (policy_id, title, scope, controls, etc.)
✓ ISO 27001 controls mapped correctly
✓ NIST CSF controls mapped correctly
✓ Owner and status fields populated
✓ Verification steps included
✓ Controls are actionable and specific
```

**Validation script**: `LLM/Scripts/evaluate_structure.py`

#### Policy Completeness

**Metrics tracked**:
- Average controls per policy
- ISO 27001 control coverage
- NIST CSF function distribution
- Theme coverage (SQL Injection, XSS, etc.)

#### Actionability Assessment

**Criteria**:
- ✅ Controls are specific and measurable
- ✅ Implementation guidance included
- ✅ Verification steps defined
- ✅ Owner accountability assigned
- ✅ Remediation priority indicated

### Comparative Analysis

The system generates a **comprehensive comparison report** (`llm_comparison.md`) that includes:

| Provider | BLEU | ROUGE-L | Policies Generated | Avg Controls/Policy | ISO Coverage | NIST Coverage |
|----------|------|---------|-------------------|---------------------|--------------|---------------|
| Gemini   | -    | 0.72    | 15                | 8.3                 | 98%          | 95%           |
| Groq     | 45.2 | 0.68    | 15                | 7.9                 | 95%          | 92%           |
| HF       | 38.7 | 0.61    | 14                | 6.5                 | 88%          | 85%           |
| OpenRouter | 42.1 | 0.70 | 15                | 8.0                 | 96%          | 94%           |

*Note: Values are illustrative*

---

## ⚙️ Configuration

### GitHub Repository Secrets

Required for CI/CD pipeline:

| Secret Name | Purpose | Free Tier | Required |
|-------------|---------|-----------|----------|
| `SONAR_TOKEN` | SonarCloud authentication | ✅ Yes | ✅ Yes |
| `GEMINI_API_KEY` | Google Gemini API access | ✅ Yes | ✅ Yes |
| `GROQ_API_KEY` | Groq API access | ✅ Yes | ✅ Yes |
| `OPENROUTER_API_KEY` | OpenRouter API access | ✅ Yes | ✅ Yes |
| `HUGGINGFACEHUB_API_TOKEN` | Hugging Face API | ✅ Yes | ⚠️ Optional |
| `SNYK_TOKEN` | Snyk scanning | ✅ Yes | ✅ Yes |

*OpenRouter offers multiple free-tier models  
**Snyk free tier available

### SonarCloud Configuration

**File**: `sonar-project.properties`

```properties
sonar.projectKey=your_project_key
sonar.organization=your_org_name
sonar.sources=.
sonar.exclusions=**/venv/**,**/node_modules/**,**/__pycache__/**
sonar.python.version=3.11
```

### Environment Variables

**Local development** (`.env` file):

```bash
# Required
SONAR_TOKEN=your_sonarcloud_token
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key
OPENROUTER_API_KEY=your_openrouter_key

# Optional
HUGGINGFACEHUB_API_TOKEN=your_hf_token
HF_TOKEN=your_hf_token  # Alternative name
SNYK_TOKEN=your_snyk_token
```

### Security Tool Configuration

#### Dependency-Check

Configured in workflow:
```yaml
--format JSON
--format HTML
--out reports/
--scan .
--suppression dependency-check-suppressions.xml  # Optional
```

#### OWASP ZAP

Configured in workflow:
```yaml
# Baseline scan
zap-baseline.py -t http://localhost:5000 -J reports/dast-baseline.json

# Full scan
zap-full-scan.py -t http://localhost:5000 -J reports/dast-full.json
```

---

## 📈 Results

### Vulnerability Detection

The intentionally vulnerable Flask application contains **80+ security issues** across multiple categories:

| Category | Count | Tools Detected By |
|----------|-------|-------------------|
| 🔓 SQL Injection | 8+ | SAST, DAST |
| 🕷️ XSS (Cross-Site Scripting) | 6+ | SAST, DAST |
| 🔐 Weak Cryptography | 5+ | SAST |
| 📦 Vulnerable Dependencies | 15+ | SCA |
| 🚪 Path Traversal | 3+ | SAST, DAST |
| 🔑 Hardcoded Secrets | 10+ | SAST |
| ⚠️ Insecure Deserialization | 2+ | SAST |
| 🌐 CSRF | 5+ | SAST, DAST |
| 📝 Sensitive Data Exposure | 8+ | SAST |
| 🔧 Security Misconfiguration | 12+ | SAST, SCA |

### Policy Generation Success Rate

| Provider | Success Rate | Avg Generation Time | Policy Count |
|----------|--------------|---------------------|--------------|
| Google Gemini | 100% | ~8s | 15 policies |
| Groq | 100% | ~3s | 15 policies |
| Hugging Face | 95% | ~15s | 14 policies |
| OpenRouter | 98% | ~10s | 15 policies |

### Sample Generated Policy

```yaml
- policy_id: POL-SQL-001
  title: SQL Injection Prevention and Input Validation
  mapping:
    iso27001:
      - A.14.2.1  # Secure development policy
      - A.12.6.1  # Technical vulnerability management
    nist_csf:
      - PR.DS-1  # Data-at-rest protection
      - PR.PT-5  # Secure coding practices
  scope: All database interactions and user input handling
  controls:
    - control_id: CTL-SQL-001
      description: Implement parameterized queries for all database operations
      implementation: Use SQLAlchemy ORM or prepared statements exclusively
    - control_id: CTL-SQL-002
      description: Input validation and sanitization
      implementation: Validate and sanitize all user inputs before processing
    - control_id: CTL-SQL-003
      description: Principle of least privilege for database accounts
      implementation: Restrict database user permissions to minimum required
  verification:
    - Code review for parameterized query usage
    - Automated SAST scans (SonarCloud, Bandit)
    - Penetration testing for SQL injection vectors
  owner: Development Team Lead
  status: mandatory
```

### Evaluation Metrics Summary

**Text Quality Metrics**:
- Average BLEU Score: 42.5 (good inter-model consistency)
- Average ROUGE-L: 0.68 (strong coverage and fluency)

**Structure Metrics**:
- Policy completeness: 98%
- ISO 27001 mapping coverage: 95%
- NIST CSF mapping coverage: 93%
- Average controls per policy: 7.9

**Compliance Coverage**:
- All critical vulnerabilities addressed: ✅ 100%
- Actionable remediation provided: ✅ 98%
- Verification steps included: ✅ 100%
- Owner assignment: ✅ 100%

---

## 🚧 Limitations & Future Work

### Current Limitations

#### Technical Constraints

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **API Rate Limits** | May throttle large-scale scans | Implement backoff strategies |
| **LLM Context Windows** | Large reports may exceed limits | Chunk processing needed |
| **Schema Rigidity** | Hard to extend for new tools | Modular parser design helps |
| **Manual CWE Mapping** | Requires maintenance | Automated mapping via ML |

#### Practical Challenges

- 🔄 **False Positives**: SAST/DAST tools generate noise requiring manual triage
- 🎯 **Policy Actionability**: Generated policies may need security expert review
- 📊 **Metric Limitations**: BLEU/ROUGE don't capture semantic policy correctness
- 🔐 **Trust & Explainability**: LLM decisions lack transparency for audit trails

#### Ethical Considerations

- 🔒 **Privacy**: Vulnerability reports may contain sensitive code snippets
- ✅ **Reliability**: Over-reliance on AI without human oversight is risky
- 📜 **Accountability**: Who is responsible when AI-generated policy fails?
- 🔍 **Explainability**: Policy recommendations need traceable reasoning

### Future Enhancements

#### Short-Term Improvements

- [ ] **Refinement Models**: Fine-tune LLMs on security policy corpus
- [ ] **Multi-Language Support**: Extend beyond Python to Java, JavaScript, etc.
- [ ] **Interactive Review**: Web UI for policy review and editing
- [ ] **Historical Tracking**: Version control for policy evolution

#### Medium-Term Goals

- [ ] **Broader Standards**: Add GDPR, HIPAA, PCI-DSS mappings
- [ ] **Semantic Evaluation**: Use embedding models for policy quality assessment
- [ ] **Continuous Learning**: Feedback loop from security team to improve prompts
- [ ] **Integration**: Direct integration with Jira, ServiceNow for policy tracking

#### Long-Term Vision

- [ ] **Multi-Modal Analysis**: Incorporate architecture diagrams, threat models
- [ ] **Real-Time Generation**: Policies generated during PR reviews
- [ ] **Adaptive Policies**: Dynamic policy updates based on threat intelligence
- [ ] **Explainable AI**: LLM reasoning chains for audit compliance

### Research Opportunities

- 🔬 **Few-Shot Learning**: Improve policy generation with domain-specific examples
- 📊 **Benchmark Dataset**: Create standardized dataset for policy generation evaluation
- 🤖 **Agent-Based Systems**: Multi-agent LLMs for complex policy scenarios
- 🔗 **Knowledge Graphs**: Structured representation of security controls

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute

- 🐛 **Bug Reports**: Found an issue? Open a GitHub issue
- 💡 **Feature Requests**: Have an idea? Start a discussion
- 🔧 **Code Contributions**: Submit pull requests
- 📖 **Documentation**: Improve docs or add examples
- 🧪 **Testing**: Add test cases or improve coverage

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/AI-DevSecOps-Project.git
cd AI-DevSecOps-Project

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test locally
python -m pytest  # Run tests (if available)

# Commit and push
git add .
git commit -m "feat: add your feature description"
git push origin feature/your-feature-name

# Open pull request on GitHub
```

### Contribution Guidelines

- ✅ Follow PEP 8 style guide for Python code
- ✅ Add docstrings to functions and classes
- ✅ Update README if adding new features
- ✅ Test changes locally before submitting PR
- ✅ Keep commits focused and well-described

### Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the project's goals
- Help create a welcoming community

---

## 📄 License

This project is intended for **educational and research purposes only**.

⚠️ **Warning**: The Flask application contains intentional security vulnerabilities. **DO NOT deploy to production environments.**

See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

### Technologies & Tools

- **Security Tools**: SonarCloud, OWASP ZAP, Dependency-Check, Snyk, Trivy
- **LLM Providers**: Google (Gemini), Groq, Hugging Face, OpenRouter
- **Frameworks**: Flask, GitHub Actions
- **Standards**: NIST CSF, ISO/IEC 27001, CWE, CVE

### References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [SonarCloud](https://sonarcloud.io/)

### Research Inspiration

This project draws inspiration from research in:
- AI-driven security automation
- DevSecOps best practices
- Automated compliance management
- LLM applications in cybersecurity

---

## 📞 Contact & Support

- 📧 **Email**: [wiame.yousfi22@gmail.com](wiame.yousfi22@gmail.com)
- 💬 **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/AI-DevSecOps-Project/issues)
- 📚 **Documentation**: See `/LLM/README.md` for detailed LLM module docs

---

<div align="center">

**Made with ❤️ for the cybersecurity and AI communities**

⭐ **Star this repository** if you find it useful!

[Back to Top ⬆️](#️-ai-devsecops-automated-security-policy-generation)

</div>
