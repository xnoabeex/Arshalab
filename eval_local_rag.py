#!/usr/bin/env python3
"""
Full metrics for local RAG models (ollama_rag_llama8b, ollama_rag_qwen14b),
computed identically to the cloud models so they sit in the same final table.

Metrics: Recall, Precision, F1, Hallucination (3-run avg),
         Consistency (keyword-based, unified method), BERTScore F1.
"""

import glob
import json
import os
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from benchmark import extract_keywords_recursive

MODELS = ["ollama_rag_llama8b_v3", "ollama_rag_qwen14b_v3", "ollama_rag_phi4"]
CASES = ["KDFS_2023", "CTF_Magnet_2022", "Hunter_4orensics"]
QDIR = Path("benchmark/questions")


def load_keywords(case):
    data = json.load(open(QDIR / f"{case}.json", encoding="utf-8"))
    out = {}
    for q in data["questions"]:
        kw = []
        extract_keywords_recursive(q.get("expected_facts", {}), kw)
        if "keywords" in q:
            kw.extend(q["keywords"])
        seen, uniq = set(), []
        for k in kw:
            key = k.lower() if isinstance(k, str) else str(k)
            if key not in seen:
                seen.add(key)
                uniq.append(k)
        out[q["id"]] = uniq
    return out


def kw_present(kw, rl):
    if isinstance(kw, list):
        return any(k.lower() in rl for k in kw)
    return kw.lower() in rl


def collect(model):
    """case -> qid -> [records...] (chronological, errors excluded)."""
    g = defaultdict(lambda: defaultdict(list))
    for f in sorted(glob.glob("benchmark_results/benchmark_*.json"),
                     key=os.path.getmtime):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        if model not in d.get("providers", []):
            continue
        dr = d.get("detailed_results", [])
        if not isinstance(dr, list):
            continue
        for r in dr:
            if r.get("provider") == model and not r.get("is_error"):
                g[r.get("case_name", "?")][r.get("question_id", "")].append(r)
    return g


def main():
    from bert_score import score
    summary = {}
    for model in MODELS:
        g = collect(model)
        print(f"\n{'='*64}\n{model}\n{'='*64}")
        all_rec, all_p, all_f, all_h = [], [], [], []
        all_kwc, all_sig = [], []
        bert_c, bert_r = [], []
        for case in CASES:
            kwmap = load_keywords(case)
            qmap = g.get(case, {})
            if not qmap:
                continue
            qd = json.load(open(QDIR / f"{case}.json", encoding="utf-8"))
            ea = {q["id"]: q.get("expected_answer", "") for q in qd["questions"]}
            rec, pr, f1, hl, kwc, sig = [], [], [], [], [], []
            for qid, runs in qmap.items():
                rec.append(sum(x["keyword_recall"] for x in runs) / len(runs))
                pr.append(sum(x.get("precision", 0) for x in runs) / len(runs))
                f1.append(sum(x.get("f1", 0) for x in runs) / len(runs))
                hl.append(sum(x.get("hallucination_rate", 0) for x in runs) / len(runs))
                # consistency on first 3 runs
                rl = [x["response"].lower() for x in runs[:3]]
                kws = kwmap.get(qid, [])
                if kws and len(rl) >= 2:
                    kwc.append(sum(1 for kw in kws
                                   if all(kw_present(kw, x) for x in rl)) / len(kws))
                    recs = [len([1 for kw in kws if kw_present(kw, x)]) / len(kws)
                            for x in rl]
                    sig.append(statistics.pstdev(recs))
                else:
                    kwc.append(1.0)
                    sig.append(0.0)
                # BERTScore: first non-empty response vs expected
                resp = next((x["response"] for x in runs if x["response"].strip()), "")
                exp = ea.get(qid, "")
                if resp.strip() and exp.strip():
                    bert_c.append(resp)
                    bert_r.append(exp)
            n = len(rec)
            print(f"  {case:<18} n={n:3d}  R={sum(rec)/n*100:5.1f}%  "
                  f"P={sum(pr)/n*100:5.1f}%  F1={sum(f1)/n*100:5.1f}%  "
                  f"H={sum(hl)/n*100:4.2f}%  KW-cons={sum(kwc)/n*100:5.1f}%")
            all_rec += rec; all_p += pr; all_f += f1; all_h += hl
            all_kwc += kwc; all_sig += sig
        # BERTScore batch
        P, R, F1 = score(bert_c, bert_r, lang="en", verbose=False, batch_size=16)
        bf1 = F1.mean().item()
        N = len(all_rec)
        s = {
            "recall": sum(all_rec)/N, "precision": sum(all_p)/N,
            "f1": sum(all_f)/N, "halluc": sum(all_h)/N,
            "kw_consistency": sum(all_kwc)/len(all_kwc),
            "recall_sigma": sum(all_sig)/len(all_sig),
            "bert_f1": bf1, "n": N,
        }
        summary[model] = s
        print(f"  {'OVERALL':<18} n={N:3d}  R={s['recall']*100:.1f}%  "
              f"P={s['precision']*100:.1f}%  F1={s['f1']*100:.1f}%  "
              f"H={s['halluc']*100:.2f}%  KW-cons={s['kw_consistency']*100:.1f}%  "
              f"σ={s['recall_sigma']:.3f}  BERT-F1={bf1:.4f}")
    json.dump(summary, open("benchmark_results/summaries/local_rag_metrics.json", "w"),
              indent=2)
    print("\nSaved: benchmark_results/summaries/local_rag_metrics.json")


if __name__ == "__main__":
    main()
