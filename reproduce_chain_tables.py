# -*- coding: utf-8 -*-
"""Reproduce the chain-reconstruction results (Tables 7 and 8, Appendix C) from the released files.

Inputs, all under benchmark_results/
  mode2_final/<model>/<case>/chain_<case>_<model>_run{1,2,3}.json   the 36 reconstructed chains
  mode2_final/<model>/<case>/*.mode2_score.json                     their stored scores
  mode2_final/<model>/<case>/evidence_<case>.json                   the 105-anchor evidence pool
  retrieval_only_baseline/                                          the baseline chains, scores and pools

Nothing here calls a language model or Elasticsearch. The chain scores are read as stored; the
match-tier count re-scores every chain with score_timeline_mode2.score and checks that the number
of matched reference events equals the stored one.

What is printed
  Table 7     composite per case and mean, step coverage, tactic coverage, ordering, hallucination
              rate and mean model-call time per model, each over the model's nine chains
  Table 8     the retrieval-only baseline beside the 36 model chains: matched reference events, step
              and tactic coverage, ordering pooled over comparable event pairs, mean composite
  Appendix C  the share of the 1,771 weightings (steps of 0.05, sum of one) under which each model
              ranks first and under which the full order of Table 7 holds, five named weightings,
              the eight shifts of a single weight by 0.10, and the tier of every reference-event match

Usage
  python reproduce_chain_tables.py
  python reproduce_chain_tables.py --rebuild-baseline DIR
      also rebuilds the baseline chains from the released pools into the new directory DIR, scores
      them and compares them with the stored baseline
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)
import score_timeline_mode2 as S  # noqa: E402
from score_timeline_jsonl import norm_ts  # noqa: E402

RESULTS = os.path.join("benchmark_results", "mode2_final")
BASELINE = os.path.join("benchmark_results", "retrieval_only_baseline")
MODELS = [("deepseek", "DeepSeek V4.1 Flash"), ("opus", "Claude Opus 4.8"),
          ("sonnet", "Claude Sonnet 4.5"), ("openai", "OpenAI GPT-5.1")]
CASES = [("kdfs", "KDFS_2023"), ("magnet", "Magnet_CTF_2022"), ("4orensics", "Hunter_4orensics")]
COMP = ["step", "tactic", "anti", "order"]
WEIGHTS = dict(step=.30, tactic=.30, anti=.25, order=.15)
NAMED = {"published": WEIGHTS, "equal": dict(step=.25, tactic=.25, anti=.25, order=.25),
         "hallucination dominant": dict(step=.20, tactic=.20, anti=.45, order=.15),
         "coverage only": dict(step=.50, tactic=.50, anti=.0, order=.0),
         "ordering heavy": dict(step=.25, tactic=.25, anti=.20, order=.30)}


def mean(v):
    return sum(v) / len(v)


def chain_rows(model, case):
    rows = []
    for f in sorted(glob.glob(os.path.join(RESULTS, model, case, "chain_*_run[123].mode2_score.json"))):
        s = json.load(open(f, encoding="utf-8"))
        c = json.load(open(f.replace(".mode2_score.json", ".json"), encoding="utf-8"))
        s["elapsed_seconds"] = c.get("elapsed_seconds")
        s["_chain"] = f.replace(".mode2_score.json", ".json")
        rows.append(s)
    assert len(rows) == 3, (model, case, len(rows))
    return rows


def pooled_order(rows):
    conc = sum(r["ordering_pairs_concordant"] for r in rows)
    disc = sum(r["ordering_pairs_discordant"] for r in rows)
    return conc / (conc + disc) * 100, conc + disc


def summary(rows):
    order_pooled, pairs = pooled_order(rows)
    return {"composite": mean([r["composite_headline"] for r in rows]) * 100,
            "step": mean([r["milestone_coverage"] for r in rows]) * 100,
            "tactic": mean([r["tactic_coverage"] for r in rows]) * 100,
            "order_mean": mean([r["ordering_accuracy"] for r in rows if r["ordering_accuracy"] is not None]) * 100,
            "order_pooled": order_pooled, "pairs": pairs,
            "halluc": mean([r["hallucination_rate"] for r in rows]) * 100,
            "matched": mean([r["matched_event_count"] for r in rows]),
            "events": mean([r["chain_event_count"] for r in rows])}


def table7():
    print("\nTable 7, chain reconstruction by model and case (percent; time in seconds)")
    print(f"{'Model':22s} {'KDFS':>6s} {'Magnet':>6s} {'Hunter':>6s} {'Mean':>6s} {'Step':>6s} {'Tactic':>6s} "
          f"{'Order':>6s} {'Halluc':>6s} {'Time':>6s}")
    out, every = {}, []
    for key, label in MODELS:
        per_case, rows = {}, []
        for case, _ in CASES:
            r = chain_rows(key, case)
            per_case[case] = mean([x["composite_headline"] for x in r]) * 100
            rows += r
        s = summary(rows)
        s["cases"] = per_case
        s["mean"] = mean(list(per_case.values()))
        s["time"] = mean([x["elapsed_seconds"] for x in rows])
        out[key] = s
        every += rows
        print(f"{label:22s} {per_case['kdfs']:6.2f} {per_case['magnet']:6.2f} {per_case['4orensics']:6.2f} "
              f"{s['mean']:6.2f} {s['step']:6.2f} {s['tactic']:6.2f} {s['order_mean']:6.2f} {s['halluc']:6.2f} "
              f"{s['time']:6.1f}")
    combos = [out[k]["cases"][c] for k, _ in MODELS for c, _ in CASES]
    print(f"mean over the twelve model-case combinations {mean(combos):.2f}; above 85 percent "
          f"{sum(c > 85 for c in combos)} of 12")
    steps = sum(r["chain_event_count"] for r in every)
    unsupported = sum(r["hallucinated_events"] for r in every)
    with_entities = sum(r["hallucination_reasons"].get("grounded_facts", 0) for r in every)
    without = sum(r["hallucination_reasons"].get("no_factual_entity_to_check", 0) for r in every)
    print(f"evidence-grounding check: {steps} steps, {unsupported} unsupported; of the steps that pass, "
          f"{with_entities} contain extracted entities found in the evidence and {without} contain none")
    return out, every


def table8(model_rows):
    base = []
    for f in sorted(glob.glob(os.path.join(BASELINE, "chain_*_baseline[12]_run0.mode2_score.json"))):
        base.append(json.load(open(f, encoding="utf-8")))
    assert len(base) == 6, len(base)
    b, m = summary(base), summary(model_rows)
    print("\nTable 8, retrieval-only baseline against the model chains")
    print(f"{'':34s} {'Anchors only':>13s} {'Anchors and a model':>20s}")
    print(f"{'Reference events matched':34s} {b['matched']:13.1f} {m['matched']:20.1f}")
    print(f"{'Step coverage (%)':34s} {b['step']:13.2f} {m['step']:20.2f}")
    print(f"{'Tactic coverage (%)':34s} {b['tactic']:13.2f} {m['tactic']:20.2f}")
    print(f"{'Ordering, pooled (%)':34s} {b['order_pooled']:13.2f} {m['order_pooled']:20.2f}")
    print(f"{'Composite (%)':34s} {b['composite']:13.2f} {m['composite']:20.2f}")
    print(f"comparable event pairs: baseline {b['pairs']}, model chains {m['pairs']}")
    return base


def ts_key(rec):
    """Sort key over the record's timestamp, tolerant of the several formats in the pools."""
    return re.sub(r"[TZ]", " ", str(rec.get("timestamp") or "")).strip()


def rebuild_baseline(out_dir, stored):
    """Take the first one (variant 1) or two (variant 2) time-stamped records of every anchor, sort them
    by time and sample the sequence evenly down to the mean length of the twelve model chains on the case."""
    assert not os.path.exists(out_dir), f"refusing to overwrite {out_dir}"
    os.makedirs(out_dir)
    stored_by_name = {os.path.basename(r["chain_file"]): r["composite_headline"] for r in stored}
    print(f"\nrebuilt baseline in {out_dir}")
    for case, name in CASES:
        length = round(mean([r["chain_event_count"] for key, _ in MODELS for r in chain_rows(key, case)]))
        ev = os.path.join(BASELINE, f"evidence_{name}.json")
        pool = json.load(open(ev, encoding="utf-8"))
        for variant in (1, 2):
            rows = []
            for anchor, recs in pool["evidence_by_anchor"].items():
                if isinstance(recs, dict):
                    recs = recs.get("records", [])
                for rec in (recs or [])[:variant]:
                    if rec.get("timestamp"):
                        rows.append((ts_key(rec), anchor, rec))
            rows.sort(key=lambda r: r[0])
            picked = [rows[int(i * len(rows) / length)] for i in range(length)]
            chain = [{"timestamp": r.get("timestamp"), "event": "[%s] _anchor=%s" % (a, a), "supporting_artifact": a,
                      "confidence_or_caveat": "retrieved", "phase": "unlabelled"} for _, a, r in picked]
            fname = f"chain_{name}_baseline{variant}_run0.json"
            dst = os.path.join(out_dir, fname)
            json.dump({"provider": "BASELINE_anchors_sort_%dpa_len%d" % (variant, length), "case": case,
                       "case_name": name, "run": 0, "evidence_file": f"evidence_{name}.json",
                       "evidence_record_count": pool["total_records"], "rows_available": len(rows),
                       "chain_event_count": len(chain), "chain": chain},
                      open(dst, "w", encoding="utf-8"), indent=2)
            rep = S.score(dst, case, evidence_path=ev)
            print(f"  {fname:44s} length {length} of {len(rows)} rows, composite "
                  f"{rep['composite_headline'] * 100:.2f}, stored {stored_by_name[fname] * 100:.2f}")


def weightings():
    means = {}
    for key, _ in MODELS:
        rows = [r for case, _ in CASES for r in chain_rows(key, case)]
        means[key] = {"step": mean([r["milestone_coverage"] or 0 for r in rows]),
                      "tactic": mean([r["tactic_coverage"] or 0 for r in rows]),
                      "anti": mean([1 - (r["hallucination_rate"] or 0) for r in rows]),
                      "order": mean([r["ordering_accuracy"] or 0 for r in rows])}

    def rank(w):
        return [k for k, _ in sorted(MODELS, key=lambda m: -sum(means[m[0]][c] * w[c] for c in COMP))]

    base = rank(WEIGHTS)
    n, first, same = 0, Counter(), 0
    for a in range(21):
        for b in range(21 - a):
            for c in range(21 - a - b):
                w = dict(step=a / 20, tactic=b / 20, anti=c / 20, order=(20 - a - b - c) / 20)
                r = rank(w)
                first[r[0]] += 1
                same += r == base
                n += 1
    print(f"\nAppendix C, {n} weightings")
    print("  first place: " + ", ".join(f"{label} {first[k] / n * 100:.1f}%" for k, label in MODELS))
    print(f"  full order of Table 7 ({' > '.join(base)}) holds under {same / n * 100:.1f}%")
    for name, w in NAMED.items():
        print(f"  {name:24s} {' > '.join(rank(w))}")
    kept = 0
    for c in COMP:
        for d in (-.10, .10):
            w = dict(WEIGHTS)
            w[c] = round(w[c] + d, 3)
            total = sum(w.values())
            kept += rank({k: v / total for k, v in w.items()}) == base
    print(f"  single-weight shifts by 0.10 that keep the order: {kept} of 8")


def tiers():
    captured = []
    match = S._match_gt_to_chain

    def minutes(t):
        if not t:
            return None
        hh, mm = t.split(":")
        return int(hh) * 60 + int(mm)

    def classify(ge, ce):
        """Tier conditions of _match_gt_to_chain, including its minute wrap inside the same hour."""
        gd, gt = norm_ts(ge.get("timestamp", ""))
        cd, ct = norm_ts(ce.get("timestamp", ""))
        if gt and cd == gd:
            hh, mm = gt.split(":")
            if ct in {gt} | {f"{int(hh):02d}:{(int(mm) + dm) % 60:02d}" for dm in (-1, 1)}:
                return 1, False
        if cd == gd:
            g, c = minutes(gt), minutes(ct)
            if g is None or c is None or abs(c - g) <= 30:
                return 2, False
        return 3, cd != gd

    def wrapped(gt_events, chain, *a, **kw):
        matched, missed, idx = match(gt_events, chain, *a, **kw)
        for gi, ci in matched:
            captured.append(classify(gt_events[gi], chain[ci]))
        return matched, missed, idx

    S._match_gt_to_chain = wrapped
    try:
        for key, _ in MODELS:
            for case, name in CASES:
                for r in chain_rows(key, case):
                    ev = os.path.join(os.path.dirname(r["_chain"]), f"evidence_{name}.json")
                    rep = S.score(r["_chain"], case, evidence_path=ev)
                    assert rep["matched_event_count"] == r["matched_event_count"], r["_chain"]
    finally:
        S._match_gt_to_chain = match
    n = len(captured)
    t = Counter(x[0] for x in captured)
    print(f"  {n} matches between reconstructed steps and reference events: tier 1 {t[1] / n * 100:.0f}%, "
          f"tier 2 {t[2] / n * 100:.0f}%, tier 3 {t[3] / n * 100:.0f}%; "
          f"on a date other than the reference date {sum(x[1] for x in captured)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rebuild-baseline", metavar="DIR", help="new directory for rebuilt baseline chains")
    args = ap.parse_args()
    _, model_rows = table7()
    stored = table8(model_rows)
    if args.rebuild_baseline:
        rebuild_baseline(args.rebuild_baseline, stored)
    weightings()
    tiers()


if __name__ == "__main__":
    main()
