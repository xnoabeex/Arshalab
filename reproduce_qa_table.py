# -*- coding: utf-8 -*-
"""Reproduce the question-answering table (Table 4) from the released answers.

Inputs
  benchmark_results/answers/<model>.json   the released answer set, 6,290 completed answers
  benchmark/questions/<case>.json          the common key, used for every model
  Elasticsearch at benchmark.ES_URL        the three public cases indexed by etl_pipeline.py,
                                           needed for the identifier check

Answer set
  Three completed runs per question and model, except Claude Opus KDFS40 and Claude Sonnet
  KDFS61 to KDFS69, which have two because their other attempts failed at the model interface.
  Where the logs held more than three completed answers to a question (GPT-5.1, Claude Sonnet and
  the three local models), the set keeps the first three in time order. For DeepSeek V3.2 the set
  holds the three runs per case that each answered all 100 questions in one session.

Measures, all from benchmark.py
  recall          check_keywords_in_response, per answer
  precision and   detect_hallucinations, per answer; precision = 1 - hallucination rate; an answer
  hallucination   with no checkable identifier counts as precision 1 and hallucination 0
  coverage        share of answers with at least one checkable identifier
  BERTScore F1    bert_score.score(lang='en') against the expected answer of the question
  consistency     compute_consistency over the three runs of a question, on questions with three
                  completed runs only

Aggregation
  Recall, precision, hallucination and BERTScore: mean over the completed runs of a question, then
  over the questions of a case, then over the three cases. Consistency: mean over the questions of
  a case with three completed runs, then over the three cases. Coverage: share over all answers.

Usage
  python reproduce_qa_table.py                 full table, BERTScore included
  python reproduce_qa_table.py --no-bert       every column except BERTScore
  python reproduce_qa_table.py --out FILE      also write per-answer results to a new JSON file
"""
import argparse
import contextlib
import io
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import benchmark as B  # noqa: E402

ANS = os.path.join(HERE, 'benchmark_results', 'answers')
QDIR = os.path.join(HERE, 'benchmark', 'questions')
CASES = ['KDFS_2023', 'CTF_Magnet_2022', 'Hunter_4orensics']
MODELS = [('DeepSeek_V3', 'DeepSeek V3.2'), ('Claude_Opus_4.1', 'Claude Opus 4.1'),
          ('Claude_Sonnet_4.5', 'Claude Sonnet 4.5'), ('OpenAI_GPT-5.1', 'OpenAI GPT-5.1'),
          ('Llama_3.1_8B', 'Llama 3.1 8B'), ('Qwen_2.5_14B', 'Qwen 2.5 14B'), ('Phi-4_14B', 'Phi-4 14B')]


def load_key():
    case_id = {c['case_name']: c['case_id'] for c in B.BENCHMARK_CASES}
    key = {}
    for c in CASES:
        with contextlib.redirect_stdout(io.StringIO()):
            _, qs = B.load_case_questions(c)
        key[c] = {q['id']: q for q in qs}
        # load_case_questions does not carry the expected answer, so it is read from the same file
        raw = json.load(open(os.path.join(QDIR, c + '.json'), encoding='utf-8'))
        for q in (raw['questions'] if isinstance(raw, dict) else raw):
            if q['id'] in key[c]:
                key[c][q['id']]['expected_answer'] = q.get('expected_answer') or ''
        assert len(key[c]) == 100, (c, len(key[c]))
    return case_id, key


def check_identifiers(cache, resp, case, case_id):
    k = (case, resp)
    if k not in cache:
        for attempt in range(5):
            d = B.detect_hallucinations(resp, case_id[case])
            if d['unchecked'] == 0:
                break
            time.sleep(2 + 3 * attempt)
        cache[k] = {'checked': d['total_checked'], 'halluc': d['hallucination_rate'],
                    'unchecked': d['unchecked'], 'flagged': d['hallucinated_facts']}
    return cache[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--no-bert', action='store_true')
    ap.add_argument('--out')
    args = ap.parse_args()
    if args.out:
        assert not os.path.exists(args.out), 'output file exists: ' + args.out
    case_id, key = load_key()

    answers, scored, cache = {}, {}, {}
    t0 = time.time()
    for m, _ in MODELS:
        rows = json.load(open(os.path.join(ANS, m + '.json'), encoding='utf-8'))
        answers[m] = rows
        out = []
        for r in rows:
            q = key[r['case']][r['question_id']]
            resp = r['response'] or ''
            d = check_identifiers(cache, resp, r['case'], case_id)
            out.append({'case': r['case'], 'qid': r['question_id'], 'run': str(r['run']),
                        'source_file': r.get('source_file'),
                        'recall': B.check_keywords_in_response(resp, q.get('keywords') or [])['recall'],
                        'checked': d['checked'], 'halluc': d['halluc'], 'unchecked': d['unchecked'],
                        'flagged': d['flagged'], 'bert_f1': None})
        scored[m] = out
        print('%-18s %d answers scored, %.0f s, unchecked %d' % (
            m, len(out), time.time() - t0, sum(1 for a in out if a['unchecked'])), flush=True)

    if not args.no_bert:
        from bert_score import score
        pairs = {}
        for m, _ in MODELS:
            for r in answers[m]:
                p = (r['response'] or '', key[r['case']][r['question_id']]['expected_answer'])
                if p[0].strip() and p[1].strip():
                    pairs.setdefault(p, None)
        plist = list(pairs)
        print('BERTScore on %d unique answer and reference pairs' % len(plist), flush=True)
        for i in range(0, len(plist), 64):
            chunk = plist[i:i + 64]
            _, _, f1 = score([p[0] for p in chunk], [p[1] for p in chunk], lang='en', batch_size=16, verbose=False)
            for p, f in zip(chunk, f1.tolist()):
                pairs[p] = f
            if (i // 64) % 10 == 0:
                print('  %d of %d, %.0f s' % (i + len(chunk), len(plist), time.time() - t0), flush=True)
        for m, _ in MODELS:
            for a, r in zip(scored[m], answers[m]):
                a['bert_f1'] = pairs.get((r['response'] or '', key[r['case']][r['question_id']]['expected_answer']))

    summary = {}
    for m, _ in MODELS:
        byq = defaultdict(list)
        resp = defaultdict(list)
        for a, r in zip(scored[m], answers[m]):
            byq[(a['case'], a['qid'])].append(a)
            resp[(a['case'], a['qid'])].append(r['response'] or '')
        cases = {}
        for c in CASES:
            v = defaultdict(list)
            for qid, q in key[c].items():
                ans = byq[(c, qid)]
                assert ans, (m, c, qid)
                v['recall'].append(sum(a['recall'] for a in ans) / len(ans))
                v['halluc'].append(sum(a['halluc'] for a in ans) / len(ans))
                bs = [a['bert_f1'] for a in ans if a['bert_f1'] is not None]
                if bs:
                    v['bert_f1'].append(sum(bs) / len(bs))
                if len(ans) == 3:
                    v['consistency'].append(
                        B.compute_consistency(resp[(c, qid)], q.get('keywords') or [])['consistency_score'])
            cases[c] = {k: sum(x) / len(x) for k, x in v.items()}
            cases[c]['questions_for_consistency'] = len(v['consistency'])
        s = {k: sum(cases[c][k] for c in CASES) / 3 for k in ('recall', 'halluc', 'consistency')}
        if not args.no_bert:
            s['bert_f1'] = sum(cases[c]['bert_f1'] for c in CASES) / 3
        s['precision'] = 1 - s['halluc']
        s['coverage'] = sum(1 for a in scored[m] if a['checked'] > 0) / len(scored[m])
        s['answers'] = len(scored[m])
        s['cases'] = cases
        summary[m] = s

    print()
    print('%-18s %6s %6s %6s %6s %7s %5s %6s %6s %6s' % (
        'Model', 'KDFS', 'Magnet', 'Hunter', 'Mean', 'Prec.', 'Hal.', 'BERT', 'Cons.', 'Cov.'))
    for m, name in MODELS:
        s = summary[m]
        c = s['cases']
        print('%-18s %6.2f %6.2f %6.2f %6.2f %7.2f %5.2f %6s %6.2f %6.1f' % (
            name, 100 * c['KDFS_2023']['recall'], 100 * c['CTF_Magnet_2022']['recall'],
            100 * c['Hunter_4orensics']['recall'], 100 * s['recall'], 100 * s['precision'], 100 * s['halluc'],
            '%.4f' % s['bert_f1'] if 'bert_f1' in s else '-', 100 * s['consistency'], 100 * s['coverage']))
    print('answers', sum(s['answers'] for s in summary.values()))
    if args.out:
        json.dump({'summary': summary, 'per_answer': scored}, open(args.out, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        print('wrote', args.out)


if __name__ == '__main__':
    main()
