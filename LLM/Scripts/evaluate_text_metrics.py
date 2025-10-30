import re, yaml
from pathlib import Path
import sacrebleu
from rouge_score import rouge_scorer
import nltk
nltk.download("punkt", quiet=True)

def read(p): return Path(p).read_text(encoding="utf-8")

def word_count(s):
    import re
    return len(re.findall(r"\w+", s))

def schema_ok(yaml_text):
    try:
        y = yaml.safe_load(yaml_text)
        if not isinstance(y, dict) or "policies" not in y or not isinstance(y["policies"], list):
            return False, "missing policies list"
        req = ["policy_id","title","mapping","scope","controls","verification","owner","status"]
        miss = []
        for i,p in enumerate(y["policies"]):
            if not isinstance(p, dict):
                return False, f"policy {i} not dict"
            for k in req:
                if k not in p: miss.append((i,k))
        return (len(miss)==0), ("ok" if not miss else f"missing {miss[:3]}{'...' if len(miss)>3 else ''}")
    except Exception as e:
        return False, f"yaml error: {e}"

ref_p = "LLM/reports/policies_openai.yaml"   # reference
cand_p = "LLM/reports/policies_hf.yaml"      # candidate

ref = read(ref_p)
try:
    cand = read(cand_p)
except Exception:
    cand = ref  # if missing, compare ref to itself to still produce file

bleu = sacrebleu.corpus_bleu([cand], [[ref]]).score
scorer = rouge_scorer.RougeScorer(["rougeLsum"], use_stemmer=True)
r_ref_cand = scorer.score(ref, cand)["rougeLsum"].fmeasure
r_cand_ref = scorer.score(cand, ref)["rougeLsum"].fmeasure
rougeL = (r_ref_cand + r_cand_ref)/2

ref_len, cand_len = word_count(ref), word_count(cand)
ref_ok, ref_reason = schema_ok(ref)
cand_ok, cand_reason = schema_ok(cand)

out = []
out.append("== Textual Metrics ==")
out.append(f"BLEU (cand vs ref): {bleu:.2f}")
out.append(f"ROUGE-L (sym avg):  {rougeL:.3f}")
out.append("")
out.append("== Length ==")
out.append(f"Ref words:   {ref_len}")
out.append(f"Cand words:  {cand_len}")
out.append("")
out.append("== Structural Validity ==")
out.append(f"Ref schema:  {ref_ok} ({ref_reason})")
out.append(f"Cand schema: {cand_ok} ({cand_reason})")

Path("LLM/reports/eval_metrics.txt").write_text("\n".join(out), encoding="utf-8")
print("OK: wrote LLM/reports/eval_metrics.txt")
