#!/usr/bin/env python3
"""Analyze failures from benchmark results."""
import json, sys

if len(sys.argv) < 2:
    sys.exit("usage: python analyze_failures.py <benchmark_run.json>")
fn = sys.argv[1]
with open(fn, encoding='utf-8') as f:
    d = json.load(f)

print(f"File: {fn}")
print(f"Avg recall: {d['summary']['deepseek']['avg_recall']:.1%}")
print()

for r in d['detailed_results']:
    qid = r['question_id']
    recall = r['keyword_recall']
    found = r['keywords_found']
    miss = r['keywords_missing']
    if recall < 0.9:
        status = 'X' if recall < 0.5 else '~'
        print(f"[{status}] {qid}: {recall:.0%} found={found} miss={miss}")
        if recall == 0.0:
            print(f"    RESPONSE: {r['response'][:200]!r}")
