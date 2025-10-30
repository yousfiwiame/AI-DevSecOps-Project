import os, json, uuid
from pathlib import Path
from dotenv import load_dotenv
from typing import Dict, List
from mappings import CWE_THEME, THEME_MAPPINGS, THEME_CONTROLS

load_dotenv()

# ---------- Helper Functions ----------
def normalize_severity(s: str) -> str:
    mapping = {
        "info":"LOW","informational":"LOW","low":"LOW",
        "medium":"MEDIUM","moderate":"MEDIUM",
        "high":"HIGH","critical":"CRITICAL"
    }
    return mapping.get(str(s).lower(), s.upper())

def detect_theme(item: Dict) -> str:
    cwe = (item.get("cwe") or "").replace("CWE-", "")
    if cwe in CWE_THEME:
        return CWE_THEME[cwe]
    text = (item.get("type","") + " " + item.get("description","") + " " + item.get("title","")).lower()
    if "sql inject" in text: return "SQL Injection"
    if "xss" in text or "cross-site" in text: return "XSS"
    if "csrf" in text: return "CSRF"
    if "path traversal" in text: return "Path Traversal"
    if "vulnerab" in text and ("dependency" in text or "component" in text):
        return "Use of Vulnerable Components"
    return "Default"

def group_findings(items: List[Dict]) -> Dict[str, List[Dict]]:
    groups = {}
    for it in items:
        it["severity"] = normalize_severity(it.get("severity","MEDIUM"))
        theme = detect_theme(it)
        groups.setdefault(theme, []).append(it)
    return groups

def build_prompt(grouped):
    tmpl = Path(__file__).with_name("prompt_template.txt").read_text(encoding="utf-8")
    return tmpl.replace("{{GROUPED_JSON}}", json.dumps(grouped, indent=2))

# ---------- LLM Functions ----------
def generate_openai(prompt):
    """Generate policies using OpenAI API - FIXED VERSION"""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[OpenAI] Missing OPENAI_API_KEY in environment/.env")
        return None
    
    try:
        from openai import OpenAI
        
        # FIXED: Initialize client with just the API key (no proxy params)
        client = OpenAI(api_key=api_key)
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[
                {"role": "system", "content": "You are a cybersecurity compliance assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[OpenAI] Error: {e}")
        print("[OpenAI] Hint: Ensure your API key is valid and you have sufficient credits")
        return None

def generate_huggingface(prompt):
    """Generate policies using Hugging Face API - IMPROVED VERSION"""
    token = os.getenv("HUGGINGFACEHUB_API_TOKEN") or os.getenv("HF_TOKEN")
    if not token:
        print("[HF] Missing HUGGINGFACEHUB_API_TOKEN or HF_TOKEN in environment/.env")
        return None
    
    try:
        from huggingface_hub import InferenceClient, whoami
        
        # Verify token is valid before trying models
        try:
            user_info = whoami(token=token)
            print(f"[HF] Token verified for user: {user_info.get('name', 'unknown')}")
        except Exception as auth_err:
            print(f"[HF] Token verification failed: {auth_err}")
            print("[HF] Get a new token at: https://huggingface.co/settings/tokens")
            return None
        
        # List of publicly accessible models that work with free tier Inference API
        preferred = (os.getenv("HF_MODEL") or "microsoft/Phi-3-mini-4k-instruct").strip()
        
        fallback_models = [
            preferred,
            "microsoft/Phi-3-mini-4k-instruct",  # Publicly accessible, good for instruction following
            "Qwen/Qwen2.5-7B-Instruct",           # Publicly accessible
            "google/gemma-2-2b-it",                # Publicly accessible
            "mistralai/Mistral-7B-Instruct-v0.2", # May require terms acceptance
            "HuggingFaceH4/zephyr-7b-beta",       # May require terms acceptance
        ]
        
        client = InferenceClient(token=token)
        
        for model in fallback_models:
            try:
                print(f"[HF] Trying model: {model}")
                
                # Try chat completion first
                try:
                    response = client.chat_completion(
                        model=model,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity compliance assistant."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=800,
                        temperature=0.2,
                    )
                    result = response.choices[0].message.content
                    print(f"[HF] ✓ Successfully used: {model}")
                    return result
                except Exception as chat_err:
                    # Fallback to text generation
                    print(f"[HF] Chat completion failed for {model}, trying text generation...")
                    response = client.text_generation(
                        model=model,
                        prompt=prompt,
                        max_new_tokens=800,
                        temperature=0.2,
                    )
                    print(f"[HF] ✓ Successfully used: {model}")
                    return response
                    
            except Exception as e:
                error_msg = str(e).lower()
                
                if "404" in error_msg or "not found" in error_msg:
                    print(f"[HF] Model {model} not accessible (404) - trying next model...")
                elif "429" in error_msg or "rate limit" in error_msg:
                    print(f"[HF] Rate limit hit for {model} - trying next model...")
                elif "gated" in error_msg or "terms" in error_msg:
                    print(f"[HF] Model {model} requires accepting terms - trying next model...")
                else:
                    print(f"[HF] Error with {model}: {str(e)[:100]}")
                
                continue
        
        # If all models failed
        print(f"\n[HF] All models failed. Check your setup:")
        print("  1. Verify your HF token at: https://huggingface.co/settings/tokens")
        print("  2. Try accepting model terms at model pages on HuggingFace")
        print("  3. Consider using OpenAI instead (more reliable)")
        return None
        
    except ImportError:
        print("[HF] Error: huggingface_hub package not installed")
        print("[HF] Install it with: pip install huggingface_hub")
        return None
    except Exception as e:
        print(f"[HF] Unexpected error: {e}")
        return None

# ---------- Main ----------
def main():
    in_file = Path("LLM/reports/unified-vulnerabilities.json")
    if not in_file.exists():
        raise SystemExit("Input file LLM/reports/unified-vulnerabilities.json not found")

    data = json.loads(in_file.read_text(encoding="utf-8"))
    items = data["findings"] if isinstance(data, dict) and "findings" in data else data
    grouped = group_findings(items)
    grouped_json = {"groups": grouped}

    prompt = build_prompt(grouped_json)

    reports_dir = Path("LLM/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # --- OpenAI policy ---
    print("\n[+] Generating with OpenAI...")
    openai_yaml = generate_openai(prompt)
    if openai_yaml:
        (reports_dir / "policies_openai.yaml").write_text(openai_yaml, encoding="utf-8")
        print("[OK] Saved OpenAI policies to LLM/reports/policies_openai.yaml")
    else:
        print("[WARN] OpenAI generation skipped or failed.")

    # --- Hugging Face policy ---
    print("\n[+] Generating with Hugging Face Inference API...")
    hf_yaml = generate_huggingface(prompt)
    if hf_yaml:
        (reports_dir / "policies_hf.yaml").write_text(hf_yaml, encoding="utf-8")
        print("[OK] Saved HF policies to LLM/reports/policies_hf.yaml")
    else:
        print("[WARN] Hugging Face generation skipped or failed.")

    print("\n[✓] Done.")

if __name__ == "__main__":
    main()