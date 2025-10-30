import yaml, statistics as stats
from pathlib import Path

def load(p):
    return yaml.safe_load(Path(p).read_text(encoding="utf-8"))

def policy_stats(y):
    cs = [len(p.get("controls",[]) or []) for p in y["policies"]]
    vs = [len(p.get("verification",[]) or []) for p in y["policies"]]
    iso = [len(p.get("mapping",{}).get("iso27001",[]) or []) for p in y["policies"]]
    nist= [len(p.get("mapping",{}).get("nist_csf",[]) or []) for p in y["policies"]]
    return dict(
      num_policies=len(y["policies"]),
      controls_avg=round(stats.mean(cs),2) if cs else 0,
      verification_avg=round(stats.mean(vs),2) if vs else 0,
      iso_avg=round(stats.mean(iso),2) if iso else 0,
      nist_avg=round(stats.mean(nist),2) if nist else 0,
    )

lines = []
for name in ["openai","hf"]:
    p = f"LLM/reports/policies_{name}.yaml"
    try:
        y = load(p)
        s = policy_stats(y)
        lines.append(f"{name}: {s}")
    except Exception as e:
        lines.append(f"{name}: error reading {p}: {e}")

Path("LLM/reports/eval_structure.txt").write_text("\n".join(lines), encoding="utf-8")
print("OK: wrote LLM/reports/eval_structure.txt")
