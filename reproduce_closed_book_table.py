# -*- coding: utf-8 -*-
"""Reproduce the closed-book control (Table 6) from the released answers.

Inputs
  benchmark_results/closed_book/closedbook_<model>_<case>.json   100 answers per model and case, given with
                                                                  the case index withheld and every forensic
                                                                  tool disabled
  benchmark/questions/<case>.json                                 the common key, used for every model

Nothing here calls a language model or Elasticsearch.

Rule
  Every key entity of a question is one entity check, unless one of its accepted values occurs in the question
  wording, in which case the question itself supplies it and it is left out. A remaining check is credited when
  benchmark.check_keywords_in_response finds the entity in the answer and none of the following holds:
    the matched value contains a token of four or more characters from the question wording;
    the matched value has one or two characters and sits inside a longer token;
    the answer presents the value as typical, an example or a guess, detected by hedging words within
    120 characters around the match.
  Table 6 gives the credited share of the checks per model and case, in percent.

Usage
  python reproduce_closed_book_table.py
"""
import contextlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)
import benchmark as B  # noqa: E402

ANSWERS = os.path.join("benchmark_results", "closed_book")
MODELS = [("deepseek", "DeepSeek V4 Flash"), ("opus", "Claude Opus 4.1"),
          ("sonnet", "Claude Sonnet 4.5"), ("openai", "OpenAI GPT-5.1")]
CASES = [("KDFS_2023", "KDFS"), ("CTF_Magnet_2022", "Magnet"), ("Hunter_4orensics", "Hunter")]
HEDGE = re.compile(
    r"\b(typically|typical|usually|usual|commonly|common|generally|general|"
    r"e\.g\.|for example|such as|might|may |would|could|often|likely|"
    r"in most|standard|default|assuming|if the|hypothetical|placeholder|"
    r"cannot|can't|without access|no access|do not have|don't have|unable)\b", re.I)


def cell(model, case):
    with contextlib.redirect_stdout(io.StringIO()):
        _, questions = B.load_case_questions(case)
    by_id = {q["id"]: q for q in questions}
    answers = json.load(open(os.path.join(ANSWERS, f"closedbook_{model}_{case}.json"), encoding="utf-8"))
    checks = credited = n_answers = 0
    for r in answers:
        q = by_id.get(r["id"])
        if not q:
            continue
        n_answers += 1
        qt = q["question"].lower()
        ans = r.get("answer") or ""
        al = ans.lower()
        missing = {str(m).lower() for m in B.check_keywords_in_response(ans, q.get("keywords") or [])["missing"]}
        qtok = set(re.findall(r"[a-z0-9@._\-]{4,}", qt))
        for entity in (q.get("keywords") or []):
            values = [str(v) for v in (entity if isinstance(entity, list) else [entity])]
            if any(v.lower() in qt for v in values):
                continue
            checks += 1
            if values[0].lower() in missing:
                continue
            hit = next((v for v in values if v.lower() in al), None)
            if hit and any(t in hit.lower() for t in qtok):
                continue
            if hit and len(hit) <= 2:
                i = al.find(hit.lower())
                left = al[i - 1] if i > 0 else " "
                right = al[i + len(hit)] if i + len(hit) < len(al) else " "
                if left.isalnum() or right.isalnum():
                    continue
            if hit:
                i = al.find(hit.lower())
                context = ans[max(0, i - 120):i + 120]
            else:
                context = ans[:240]
            if HEDGE.search(context):
                continue
            credited += 1
    return n_answers, checks, credited


def main():
    print("Table 6, closed-book recall over the key entities the question wording does not supply, in percent")
    print(f"{'Model':20s} " + " ".join(f"{label:>7s}" for _, label in CASES))
    total_answers = total_checks = total_credited = 0
    worst = 0.0
    for key, label in MODELS:
        shares = []
        for case, _ in CASES:
            n, checks, credited = cell(key, case)
            total_answers += n
            total_checks += checks
            total_credited += credited
            shares.append(credited / checks * 100)
        worst = max(worst, max(shares))
        print(f"{label:20s} " + " ".join(f"{s:7.1f}" for s in shares))
    print(f"{total_answers} answers, {total_checks} entity checks, {total_credited} credited "
          f"({total_credited / total_checks * 100:.1f} percent); highest model-case share {worst:.1f} percent")


if __name__ == "__main__":
    main()
