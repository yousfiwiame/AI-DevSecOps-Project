#!/usr/bin/env python3
"""
Generate security policies using LLM APIs (Gemini, Groq, Hugging Face, OpenRouter).
This script loads unified vulnerabilities and generates security policies
conforming to ISO 27001 and NIST CSF standards.

UPDATED VERSION with correct Gemini and OpenRouter.ai free models support.
"""
import os
import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

try:
    from huggingface_hub import InferenceClient
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False
    print("Warning: huggingface_hub package not available. Hugging Face generation will be skipped.")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("Warning: google-generativeai package not available. Gemini generation will be skipped.")

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("Warning: groq package not available. Groq generation will be skipped.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests package not available. OpenRouter generation will be skipped.")

from dotenv import load_dotenv
import yaml

from mappings import get_theme_from_cwe, get_iso27001_controls, get_nist_csf_controls, get_suggested_controls

# Load environment variables
load_dotenv()


def load_vulnerabilities() -> List[Dict[str, Any]]:
    """Load unified vulnerabilities from JSON file"""
    vuln_file = Path(__file__).parent.parent / "reports" / "unified-vulnerabilities.json"
    
    if not vuln_file.exists():
        print(f"Error: {vuln_file} not found")
        print("Make sure parse_reports.py has been run first to generate unified report")
        sys.exit(1)
    
    with open(vuln_file, 'r', encoding='utf-8') as f:
        vulnerabilities = json.load(f)
    
    if not vulnerabilities:
        print("Warning: No vulnerabilities found in unified report")
        print("Policies may be generic or empty")
    
    return vulnerabilities


def group_vulnerabilities_by_theme(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group vulnerabilities by vulnerability theme"""
    grouped = {}
    
    for vuln in vulnerabilities:
        cwe = vuln.get('cwe', 'N/A')
        theme = get_theme_from_cwe(cwe)
        
        # Also check vulnerability type/name for theme detection
        vuln_name = str(vuln.get('vulnerability') or vuln.get('type', '')).lower()
        
        # Refine theme based on vulnerability name
        if 'sql injection' in vuln_name or 'sqli' in vuln_name:
            theme = "SQL Injection"
        elif 'xss' in vuln_name or 'cross-site scripting' in vuln_name:
            theme = "Cross-Site Scripting (XSS)"
        elif 'csrf' in vuln_name or 'cross-site request forgery' in vuln_name:
            theme = "Cross-Site Request Forgery (CSRF)"
        elif 'dependency' in vuln_name or vuln.get('package'):
            theme = "Dependency Vulnerability"
        elif 'command injection' in vuln_name or 'os command' in vuln_name:
            theme = "OS Command Injection"
        elif 'authentication' in vuln_name or 'password' in vuln_name:
            theme = "Improper Authentication"
        elif 'encryption' in vuln_name or 'cryptographic' in vuln_name:
            theme = "Weak Cryptographic Algorithm"
        elif 'input validation' in vuln_name or 'path traversal' in vuln_name:
            theme = "Improper Input Validation"
        elif 'session' in vuln_name:
            theme = "Session Fixation"
        elif 'information disclosure' in vuln_name or 'information exposure' in vuln_name:
            theme = "Information Disclosure"
        
        if theme not in grouped:
            grouped[theme] = []
        
        grouped[theme].append(vuln)
    
    return grouped


def build_prompt(grouped_vulns: Dict[str, List[Dict[str, Any]]]) -> str:
    """Build prompt for LLM from grouped vulnerabilities"""
    template_path = Path(__file__).parent / "prompt_template.txt"
    
    with open(template_path, 'r', encoding='utf-8') as f:
        template = f.read()
    
    # Build grouped JSON structure
    grouped_data = {}
    for theme, vulns in grouped_vulns.items():
        grouped_data[theme] = {
            "count": len(vulns),
            "severity_distribution": {
                "CRITICAL": len([v for v in vulns if v.get('severity') == 'CRITICAL']),
                "HIGH": len([v for v in vulns if v.get('severity') == 'HIGH']),
                "MEDIUM": len([v for v in vulns if v.get('severity') == 'MEDIUM']),
                "LOW": len([v for v in vulns if v.get('severity') == 'LOW']),
            },
            "iso27001_controls": get_iso27001_controls(theme),
            "nist_csf_controls": get_nist_csf_controls(theme),
            "suggested_controls": get_suggested_controls(theme),
            "sample_vulnerabilities": vulns[:3],  # Include first 3 as examples
        }
    
    grouped_json = json.dumps(grouped_data, indent=2)
    
    prompt = template.replace("{{GROUPED_JSON}}", grouped_json)
    return prompt


def generate_with_gemini(prompt: str) -> str:
    """Generate policies using Google Gemini API (FREE tier available!)"""
    if not GEMINI_AVAILABLE:
        raise ImportError("google-generativeai package not available")
    
    api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
    if not api_key:
        raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY environment variable not set")
    
    try:
        # Configure Gemini API
        genai.configure(api_key=api_key)
        
        # Try Gemini models in order of preference (correct model names for 2025)
        models_to_try = [
            'gemini-2.0-flash-exp',      # Gemini 2.0 Flash Experimental (FREE)
            'gemini-1.5-flash',           # Gemini 1.5 Flash (FREE tier)
            'gemini-1.5-flash-latest',    # Latest Gemini 1.5 Flash
            'gemini-1.5-pro-latest',      # Gemini 1.5 Pro
            'gemini-pro',                 # Legacy Gemini Pro
        ]
        
        for model_name in models_to_try:
            try:
                print(f"   Trying Gemini model: {model_name}")
                model = genai.GenerativeModel(model_name)
                
                # Generate response
                response = model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.7,
                        max_output_tokens=4000,
                    )
                )
                
                result = response.text.strip()
                if result and len(result) > 50:
                    print(f"   ✅ Success with Gemini model: {model_name}")
                    return result
                else:
                    print(f"   ⚠️  Model {model_name} returned empty/short response")
            except Exception as e:
                error_msg = str(e)
                if 'quota' in error_msg.lower() or '429' in error_msg:
                    print(f"   ⚠️  Model {model_name} quota exceeded, trying next model...")
                    continue
                elif 'not found' in error_msg.lower() or '404' in error_msg:
                    print(f"   ⚠️  Model {model_name} not available (404), trying next model...")
                    continue
                elif '403' in error_msg or 'permission' in error_msg.lower() or 'not enabled' in error_msg.lower():
                    print(f"   ⚠️  Model {model_name} not enabled for your API key (403)")
                    print(f"      💡 Enable it at: https://aistudio.google.com/apikey")
                    continue
                elif 'api key' in error_msg.lower() or '401' in error_msg:
                    print(f"   ⚠️  Invalid Gemini API key (401)")
                    print(f"      💡 Get a free key at: https://aistudio.google.com/apikey")
                    continue
                else:
                    print(f"   ⚠️  Model {model_name} failed: {error_msg[:150]}")
                    continue
        
        # If all models failed
        raise Exception("All Gemini models failed")
        
    except Exception as e:
        raise Exception(f"Gemini API failed: {str(e)}")


def generate_with_groq(prompt: str) -> str:
    """Generate policies using Groq API (FREE tier available!)"""
    if not GROQ_AVAILABLE:
        raise ImportError("groq package not available")
    
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable not set")
    
    try:
        client = Groq(api_key=api_key)
        
        # Try Groq models in order of preference (all free tier)
        models_to_try = [
            'llama-3.3-70b-versatile',  # Latest Llama 3.3 70B
            'llama-3.1-70b-versatile',  # Llama 3.1 70B (most capable)
            'llama-3.1-8b-instant',     # Fast and efficient
            'mixtral-8x7b-32768',       # Good alternative
        ]
        
        for model_name in models_to_try:
            try:
                print(f"   Trying Groq model: {model_name}")
                
                chat_completion = client.chat.completions.create(
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity compliance assistant specialized in generating security policies based on vulnerability findings."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    model=model_name,
                    temperature=0.7,
                    max_tokens=4000,
                )
                
                result = chat_completion.choices[0].message.content.strip()
                if result and len(result) > 50:
                    print(f"   ✅ Success with Groq model: {model_name}")
                    return result
                else:
                    print(f"   ⚠️  Model {model_name} returned empty/short response")
            except Exception as e:
                error_msg = str(e)
                print(f"   ⚠️  Model {model_name} failed: {error_msg[:80]}")
                continue
        
        raise Exception("All Groq models failed")
        
    except Exception as e:
        raise Exception(f"Groq API failed: {str(e)}")


def generate_with_openrouter(prompt: str, model_name: str, model_display_name: str) -> str:
    """Generate policies using OpenRouter.ai API (FREE tier models)"""
    if not REQUESTS_AVAILABLE:
        raise ImportError("requests package not available")
    
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/your-repo",
            "X-Title": "Security Policy Generation"
        }
        
        payload = {
            "model": model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity compliance assistant specialized in generating security policies based on vulnerability findings. Generate policies in valid YAML format."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 4000
        }
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=120,
        )
        response.raise_for_status()
        
        result_data = response.json()
        result = result_data["choices"][0]["message"]["content"].strip()
        
        if result and len(result) > 50:
            print(f"   ✅ Success with OpenRouter model: {model_display_name}")
            return result
        else:
            raise Exception(f"Model {model_display_name} returned empty/short response")
            
    except requests.exceptions.HTTPError as e:
        error_str = str(e)
        if response.status_code == 429:
            raise Exception(f"OpenRouter API rate limit exceeded. Please wait and try again.")
        elif response.status_code == 401:
            raise Exception(f"Invalid OpenRouter API key. Please check your OPENROUTER_API_KEY.")
        elif response.status_code == 402:
            raise Exception(f"Insufficient credits for OpenRouter. Please add credits to your account.")
        elif response.status_code == 400:
            # Try to get more details from the response
            try:
                error_detail = response.json()
                raise Exception(f"OpenRouter API error (400): {error_detail}")
            except:
                raise Exception(f"OpenRouter API error (400): Bad Request - Model may not be available")
        else:
            raise Exception(f"OpenRouter API error ({response.status_code}): {error_str}")
    except Exception as e:
        error_str = str(e)
        if 'quota' in error_str.lower() or 'limit' in error_str.lower():
            raise Exception(f"OpenRouter API limit exceeded: {error_str}")
        raise Exception(f"OpenRouter API failed for {model_display_name}: {error_str}")


def generate_with_huggingface(prompt: str) -> str:
    """Generate policies using Hugging Face Inference API"""
    if not HF_AVAILABLE:
        raise ImportError("huggingface_hub package not available")
    
    api_token = os.getenv('HUGGINGFACEHUB_API_TOKEN') or os.getenv('HF_TOKEN')
    if not api_token:
        raise ValueError("HUGGINGFACEHUB_API_TOKEN or HF_TOKEN environment variable not set")
    
    # Updated model list - prioritize models that work with Inference API
    models_to_try = [
        ('HuggingFaceH4/zephyr-7b-beta', 'chat'),
        ('mistralai/Mistral-7B-Instruct-v0.2', 'chat'),
        ('microsoft/Phi-3-mini-4k-instruct', 'chat'),
        ('meta-llama/Llama-2-7b-chat-hf', 'chat'),
        ('google/flan-t5-xxl', 'text_generation'),
    ]
    
    try:
        client = InferenceClient(token=api_token)
    except Exception as e:
        raise Exception(f"Failed to initialize Hugging Face client: {e}")
    
    for model_name, api_method in models_to_try:
        try:
            print(f"   Trying model: {model_name} (method: {api_method})")
            
            if api_method == 'chat':
                messages = [
                    {"role": "user", "content": prompt}
                ]
                response = client.chat_completion(
                    model=model_name,
                    messages=messages,
                    max_tokens=2000,
                    temperature=0.7,
                )
                # Extract text from chat completion response
                if isinstance(response, dict):
                    choices = response.get('choices', [])
                    if choices and isinstance(choices[0], dict):
                        message = choices[0].get('message', {})
                        result = message.get('content', '') if isinstance(message, dict) else str(message)
                    else:
                        result = response.get('content', str(response))
                elif hasattr(response, 'choices'):
                    try:
                        result = response.choices[0].message.content
                    except (AttributeError, IndexError):
                        result = str(response)
                else:
                    result = str(response)
            else:
                response = client.text_generation(
                    prompt,
                    model=model_name,
                    max_new_tokens=2000,
                    temperature=0.7,
                    return_full_text=False,
                )
                result = response.strip() if isinstance(response, str) else str(response).strip()
            
            if result and len(result) > 50:
                print(f"   ✅ Success with model: {model_name}")
                return result
            else:
                print(f"   ⚠️  Model {model_name} returned empty/short response")
        except Exception as e:
            error_msg = str(e)
            if '404' in error_msg or 'not found' in error_msg.lower():
                print(f"   ⚠️  Model {model_name} not available via Inference API (404)")
            elif '503' in error_msg or 'loading' in error_msg.lower():
                print(f"   ⚠️  Model {model_name} is loading, skipping...")
            elif '401' in error_msg or 'unauthorized' in error_msg.lower():
                print(f"   ⚠️  Model {model_name} requires authentication or access approval")
            elif '403' in error_msg or 'forbidden' in error_msg.lower():
                print(f"   ⚠️  Model {model_name} requires gated access approval")
            else:
                print(f"   ⚠️  Model {model_name} failed: {error_msg[:100]}")
            continue
    
    print(f"\n   ⚠️  All Hugging Face models unavailable via Inference API")
    print(f"   ℹ️  This is common - many models require special access or Inference Endpoints")
    raise Exception("Hugging Face models unavailable - skipping HF generation")


def extract_yaml_from_response(response: str) -> Dict[str, Any]:
    """Extract YAML content from LLM response - handles various formats"""
    yaml_content = None
    
    # Try to find YAML in markdown code blocks (various formats)
    code_block_patterns = [
        ("```yaml\n", "```"),
        ("```yml\n", "```"),
        ("```YAML\n", "```"),
        ("```YML\n", "```"),
        ("```yaml", "```"),
        ("```yml", "```"),
        ("```\n", "```"),  # Generic code block
    ]
    
    for start_marker, end_marker in code_block_patterns:
        if start_marker in response:
            start_idx = response.find(start_marker)
            if start_idx == -1:
                continue
            
            # Skip the marker
            content_start = start_idx + len(start_marker)
            
            # Find the end of the code block
            end_idx = response.find(end_marker, content_start)
            if end_idx == -1:
                yaml_content = response[content_start:].strip()
            else:
                yaml_content = response[content_start:end_idx].strip()
            
            if yaml_content:
                break
    
    # If no code block found, look for "policies:" keyword
    if not yaml_content and "policies:" in response:
        start_idx = response.find("policies:")
        yaml_content = response[start_idx:].strip()
        
        # Try to find a reasonable end point
        lines = yaml_content.split('\n')
        yaml_lines = []
        for line in lines:
            # Stop if we hit explanatory text
            if line.strip() and not line.strip().startswith((' ', '-', 'policies:', 'policy_id:', 'title:', 'mapping:', 'iso27001:', 'nist_csf:', 'scope:', 'controls:', 'verification:', 'owner:', 'status:', 'created_at:', 'last_updated:', 'description:', 'id:', 'implementation:')):
                if any(keyword in line.lower() for keyword in ['note:', 'important:', 'remember:', 'please', 'this policy', 'these policies']):
                    break
            yaml_lines.append(line)
        yaml_content = '\n'.join(yaml_lines).strip()
    
    # If still no YAML content, try the entire response
    if not yaml_content:
        yaml_content = response.strip()
    
    try:
        parsed = yaml.safe_load(yaml_content)
        if parsed is None or not isinstance(parsed, dict):
            return {"policies": []}
        return parsed
    except yaml.YAMLError as e:
        print(f"⚠️  YAML parsing failed: {e}")
        print("📄 Attempting to fix common YAML issues...")
        
        # Enhanced YAML fixing
        fixed_yaml = fix_yaml_structure(yaml_content)
        
        try:
            parsed = yaml.safe_load(fixed_yaml)
            if parsed and isinstance(parsed, dict):
                print(f"✅ Successfully parsed after fixing YAML structure")
                return parsed
        except yaml.YAMLError as e2:
            print(f"⚠️  YAML still invalid after fixes: {e2}")
            # Try one more aggressive fix
            try:
                fixed_yaml2 = fix_yaml_aggressive(yaml_content)
                parsed = yaml.safe_load(fixed_yaml2)
                if parsed and isinstance(parsed, dict):
                    print(f"✅ Successfully parsed after aggressive fixes")
                    return parsed
            except:
                pass
            
        print(f"❌ Could not parse YAML after all fixes")
        print("Response preview (first 500 chars):", response[:500])
        return {"policies": [], "raw_response": yaml_content[:500]}


def fix_yaml_structure(yaml_content: str) -> str:
    """Fix common YAML structure issues - handles indentation and list formatting"""
    if not yaml_content:
        return ""
    
    lines = yaml_content.split('\n')
    fixed_lines = []
    in_policies = False
    in_policy_item = False
    in_controls = False
    in_control_item = False
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Preserve empty lines
        if not stripped:
            fixed_lines.append("")
            continue
        
        # Track context
        if stripped.startswith('policies:'):
            in_policies = True
            in_policy_item = False
            in_controls = False
            in_control_item = False
            fixed_lines.append(line)
            continue
        elif stripped.startswith('- policy_id:') or (stripped.startswith('-') and 'policy_id:' in stripped):
            in_policy_item = True
            in_controls = False
            in_control_item = False
            # Ensure proper indentation (2 spaces for policy items)
            if not line.startswith('  '):
                fixed_lines.append('  ' + stripped)
            else:
                fixed_lines.append(line)
            continue
        elif stripped.startswith('controls:'):
            in_controls = True
            in_control_item = False
            # Controls should be indented 4 spaces (under policy item)
            if not line.startswith('    '):
                fixed_lines.append('    ' + stripped)
            else:
                fixed_lines.append(line)
            continue
        elif (stripped.startswith('- id:') or (stripped.startswith('-') and 'id:' in stripped)) and in_controls:
            in_control_item = True
            # Control items should be indented 6 spaces (under controls:)
            if not line.startswith('      '):
                fixed_lines.append('      ' + stripped)
            else:
                fixed_lines.append(line)
            continue
        
        # Fix indentation for control item properties
        if in_control_item and not stripped.startswith('-'):
            # Properties of control items should be indented 8 spaces
            if ':' in stripped:
                if not line.startswith('        '):
                    fixed_lines.append('        ' + stripped)
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        # Fix indentation for policy item properties (not controls)
        elif in_policy_item and not in_controls and not stripped.startswith('-'):
            # Properties of policy items should be indented 4 spaces
            if ':' in stripped:
                if not line.startswith('    '):
                    fixed_lines.append('    ' + stripped)
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        # Fix misformatted control items (when they appear at wrong indentation)
        elif in_controls and stripped.startswith('- id:'):
            in_control_item = True
            fixed_lines.append('      ' + stripped)
        # Fix misformatted list items in controls
        elif in_controls and stripped.startswith('-') and 'id:' not in stripped:
            # This might be a control property that was formatted as a list item
            fixed_lines.append('        ' + stripped[1:].strip())
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def fix_yaml_aggressive(yaml_content: str) -> str:
    """More aggressive YAML fixing - rebuilds structure"""
    if not yaml_content or 'policies:' not in yaml_content:
        return yaml_content
    
    # Extract just the policies section
    start_idx = yaml_content.find('policies:')
    if start_idx == -1:
        return yaml_content
    
    yaml_section = yaml_content[start_idx:]
    lines = yaml_section.split('\n')
    
    fixed_lines = ['policies:']
    in_policy = False
    in_controls = False
    current_policy = {}
    current_control = {}
    
    i = 1  # Skip 'policies:' line
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        if not stripped:
            i += 1
            continue
        
        # Detect policy start
        if stripped.startswith('- policy_id:') or (stripped.startswith('-') and 'policy_id:' in stripped):
            if current_policy:
                # Save previous policy
                fixed_lines.append(f"  - policy_id: {current_policy.get('policy_id', 'POL-UNKNOWN')}")
                for key, val in current_policy.items():
                    if key != 'policy_id' and key != 'controls':
                        fixed_lines.append(f"    {key}: {val}")
                if current_policy.get('controls'):
                    fixed_lines.append("    controls:")
                    for ctrl in current_policy['controls']:
                        fixed_lines.append(f"      - id: {ctrl.get('id', 'CTRL-UNKNOWN')}")
                        for ckey, cval in ctrl.items():
                            if ckey != 'id':
                                fixed_lines.append(f"        {ckey}: {cval}")
            
            # Start new policy
            current_policy = {}
            in_policy = True
            in_controls = False
            
            # Extract policy_id
            if 'policy_id:' in stripped:
                policy_id = stripped.split('policy_id:')[1].strip().strip('"\'')
                current_policy['policy_id'] = policy_id
            i += 1
            continue
        
        # Detect controls section
        if stripped == 'controls:' or (stripped.startswith('controls:') and in_policy):
            in_controls = True
            if 'controls' not in current_policy:
                current_policy['controls'] = []
            i += 1
            continue
        
        # Detect control item
        if stripped.startswith('- id:') or (stripped.startswith('-') and 'id:' in stripped and in_controls):
            if current_control:
                current_policy['controls'].append(current_control)
            current_control = {}
            if 'id:' in stripped:
                ctrl_id = stripped.split('id:')[1].strip().strip('"\'')
                current_control['id'] = ctrl_id
            i += 1
            continue
        
        # Parse key-value pairs
        if ':' in stripped and not stripped.startswith('-'):
            key, val = stripped.split(':', 1)
            key = key.strip()
            val = val.strip().strip('"\'')
            
            if in_controls and current_control:
                current_control[key] = val
            elif in_policy and current_policy:
                current_policy[key] = val
        
        i += 1
    
    # Save last policy and control
    if current_control:
        current_policy['controls'].append(current_control)
    if current_policy:
        fixed_lines.append(f"  - policy_id: {current_policy.get('policy_id', 'POL-UNKNOWN')}")
        for key, val in current_policy.items():
            if key != 'policy_id' and key != 'controls':
                fixed_lines.append(f"    {key}: {val}")
        if current_policy.get('controls'):
            fixed_lines.append("    controls:")
            for ctrl in current_policy['controls']:
                fixed_lines.append(f"      - id: {ctrl.get('id', 'CTRL-UNKNOWN')}")
                for ckey, cval in ctrl.items():
                    if ckey != 'id':
                        fixed_lines.append(f"        {ckey}: {cval}")
    
    return '\n'.join(fixed_lines)


def save_policies(policies: Dict[str, Any], output_file: Path):
    """Save policies to YAML file"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(policies, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    print(f"✅ Policies saved to: {output_file}")


def main():
    """Main function"""
    print("=" * 60)
    print("Security Policy Generation with LLMs")
    print("🆓 FREE TIER MODELS: Gemini, Groq, Hugging Face, OpenRouter.ai")
    print("=" * 60)
    
    # Load vulnerabilities
    print("\n📥 Loading vulnerabilities...")
    vulnerabilities = load_vulnerabilities()
    print(f"   Found {len(vulnerabilities)} vulnerabilities")
    
    # Group by theme
    print("\n🔄 Grouping vulnerabilities by theme...")
    grouped = group_vulnerabilities_by_theme(vulnerabilities)
    print(f"   Found {len(grouped)} vulnerability themes:")
    for theme, vulns in grouped.items():
        print(f"   - {theme}: {len(vulns)} vulnerabilities")
    
    # Build prompt
    print("\n📝 Building prompt...")
    prompt = build_prompt(grouped)
    
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Track successful generations
    successful_models = []
    
    # Try models in priority order: FREE FIRST!
    
    # 1. Try Gemini (FREE - priority #1)
    if GEMINI_AVAILABLE:
        try:
            print("\n🤖 Generating policies with Google Gemini (FREE tier)...")
            gemini_response = generate_with_gemini(prompt)
            gemini_policies = extract_yaml_from_response(gemini_response)
            
            output_file = reports_dir / "policies_gemini.yaml"
            save_policies(gemini_policies, output_file)
            
            policy_count = len(gemini_policies.get('policies', []))
            print(f"   ✅ Generated {policy_count} policies")
            successful_models.append("Gemini")
        except Exception as e:
            print(f"   ⚠️  Gemini generation failed: {e}")
    
    # 2. Try Groq (FREE - priority #2)
    if GROQ_AVAILABLE:
        try:
            print("\n🤖 Generating policies with Groq (FREE tier)...")
            groq_response = generate_with_groq(prompt)
            groq_policies = extract_yaml_from_response(groq_response)
            
            output_file = reports_dir / "policies_groq.yaml"
            save_policies(groq_policies, output_file)
            
            policy_count = len(groq_policies.get('policies', []))
            print(f"   ✅ Generated {policy_count} policies")
            successful_models.append("Groq")
        except Exception as e:
            print(f"   ⚠️  Groq generation skipped: {e}")
    
    # 3. Try Hugging Face (FREE but often unavailable - priority #3)
    if HF_AVAILABLE:
        try:
            print("\n🤖 Generating policies with Hugging Face...")
            hf_response = generate_with_huggingface(prompt)
            if isinstance(hf_response, str):
                hf_policies = extract_yaml_from_response(hf_response)
            else:
                hf_policies = {"policies": []}
            
            output_file = reports_dir / "policies_hf.yaml"
            save_policies(hf_policies, output_file)
            
            policy_count = len(hf_policies.get('policies', []))
            print(f"   ✅ Generated {policy_count} policies")
            successful_models.append("Hugging Face")
        except Exception as e:
            print(f"   ⚠️  Hugging Face generation skipped: {e}")
    
    # 4. Try OpenRouter.ai FREE models (priority #4)
    # CORRECT FREE MODEL NAMES from OpenRouter (use :free suffix)
    if REQUESTS_AVAILABLE:
        openrouter_models = [
            # Meta Models (FREE)
            ("meta-llama/llama-3.1-8b-instruct:free", "Llama 3.1 8B Instruct Free"),
            ("meta-llama/llama-3.2-3b-instruct:free", "Llama 3.2 3B Instruct Free"),
            
            # Mistral Models (FREE)
            ("mistralai/mistral-7b-instruct:free", "Mistral 7B Instruct Free"),
            
            # HuggingFace Models (FREE)
            ("huggingfaceh4/zephyr-7b-beta:free", "Zephyr 7B Beta Free"),
            
            # Google Models (FREE) - via OpenRouter
            ("google/gemini-flash-1.5", "Gemini Flash 1.5"),
            ("google/gemini-flash-1.5-8b", "Gemini Flash 1.5 8B"),
            
            # Nous Research (FREE)
            ("nousresearch/hermes-3-llama-3.1-405b:free", "Hermes 3 Llama 405B Free"),
            
            # Dolphin Models (FREE)
            ("cognitivecomputations/dolphin-mixtral-8x7b:free", "Dolphin Mixtral 8x7B Free"),
        ]
        
        for model_name, model_display_name in openrouter_models:
            try:
                print(f"\n🤖 Generating policies with OpenRouter ({model_display_name}) (FREE tier)...")
                openrouter_response = generate_with_openrouter(prompt, model_name, model_display_name)
                openrouter_policies = extract_yaml_from_response(openrouter_response)
                
                # Create safe filename from model display name
                safe_filename = model_display_name.lower().replace(" ", "_").replace(".", "").replace("/", "_")
                output_file = reports_dir / f"policies_openrouter_{safe_filename}.yaml"
                save_policies(openrouter_policies, output_file)
                
                policy_count = len(openrouter_policies.get('policies', []))
                print(f"   ✅ Generated {policy_count} policies")
                successful_models.append(f"OpenRouter: {model_display_name}")
            except Exception as e:
                print(f"   ⚠️  OpenRouter ({model_display_name}) generation skipped: {e}")
    
    # Final summary
    print("\n" + "=" * 60)
    if len(successful_models) == 0:
        print("❌ ERROR: All models failed!")
        print("\n💡 SOLUTIONS:")
        print("1. Get FREE Gemini API key: https://aistudio.google.com/apikey")
        print("2. Get FREE Groq API key: https://console.groq.com/")
        print("3. Get FREE OpenRouter API key: https://openrouter.ai/keys")
        print("4. Set keys in environment: GEMINI_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY")
        print("=" * 60)
        sys.exit(1)
    else:
        print(f"✅ Success! Generated policies with {len(successful_models)} models:")
        for model in successful_models:
            print(f"   ✅ {model}")
        print(f"\n📊 Comparative study ready with {len(successful_models)} models!")
        print("=" * 60)


if __name__ == "__main__":
    main()