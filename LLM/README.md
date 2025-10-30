## LLM module

This folder contains the Large Language Model (LLM) tooling for policy generation, text/structure evaluation, and unified security report handling used by the project.

### Contents

- `Scripts/`
  - `generate_policies.py`: Generate policy files for different providers (OpenAI, Hugging Face) from a prompt template and mappings.
  - `evaluate_text_metrics.py`: Compute text-level metrics (e.g., length, toxicity/sentiment placeholders, readability) for model outputs.
  - `evaluate_structure.py`: Check structural compliance of responses (JSON/schema keys, required sections, etc.).
  - `mappings.py`: Centralized mappings/config used by the scripts (models, policies, categories).
  - `prompt_template.txt`: Base prompt template used by `generate_policies.py`.

- `reports/`
  - `policies_openai.yaml`: Generated policies targeting OpenAI-compatible models.
  - `policies_hf.yaml`: Generated policies targeting Hugging Face pipelines/models.
  - `unified-vulnerabilities.json`: Unified, normalized security findings consumed by the app.
  - `unified-vulnerabilities.sample.json`: Sample of the unified format for reference/testing.

### Prerequisites

- Python 3.10+
- Dependencies from the project root `requirements.txt`:
  ```bash
  pip install -r requirements.txt
  ```
- Optional provider credentials in a local `.env` (kept out of git):
  - `OPENAI_API_KEY`
  - `HF_API_TOKEN`

### Quick start

1) Generate/update policy files from the template and mappings:
```bash
python LLM/Scripts/generate_policies.py \
  --template LLM/Scripts/prompt_template.txt \
  --mappings  LLM/Scripts/mappings.py \
  --out-openai LLM/reports/policies_openai.yaml \
  --out-hf     LLM/reports/policies_hf.yaml
```

2) Evaluate text metrics on a file with model outputs:
```bash
python LLM/Scripts/evaluate_text_metrics.py \
  --inputs path/to/outputs.json \
  --report LLM/reports/text_metrics.json
```

3) Validate structure of responses (e.g., required keys/sections):
```bash
python LLM/Scripts/evaluate_structure.py \
  --inputs path/to/outputs.json \
  --schema path/to/schema.json \
  --report LLM/reports/structure_eval.json
```

4) Work with unified vulnerabilities report:
```bash
python scripts/parse_reports.py               # normalize sources → LLM/reports/unified-vulnerabilities.json
python scripts/generate_sca_summary.py        # produce summary views from unified report
```

### Notes & conventions

- `.env` must not be committed; ensure `.gitignore` contains `.env`. If already tracked, remove with:
  ```bash
  git rm --cached .env && git commit -m "chore: stop tracking .env"
  ```
- Policy files are generated artifacts; commit them when they are the intended source of truth for deployments.
- Keep `mappings.py` minimal and declarative; avoid provider-specific logic in mappings.

### Typical workflow

1. Update `prompt_template.txt` and `mappings.py` as needed.
2. Run `generate_policies.py` to refresh `policies_*.yaml`.
3. Produce model outputs (outside this folder), then run `evaluate_text_metrics.py` and `evaluate_structure.py` to check quality/compliance.
4. Aggregate scanner outputs with `scripts/parse_reports.py`, then generate summaries via `scripts/generate_sca_summary.py`.

### Troubleshooting

- Missing API keys: set `OPENAI_API_KEY` or `HF_API_TOKEN` in `.env`.
- Permission errors on push: open a PR from your feature branch rather than pushing directly to `main`.
- Encoding issues: ensure UTF-8 when reading/writing reports.

### Future improvements

- Add real toxicity/readability models for `evaluate_text_metrics.py`.
- Add JSON Schema validation to `evaluate_structure.py` with rich error reporting.
- CI checks that (a) policies regenerate cleanly and (b) unified report schema stays consistent.


