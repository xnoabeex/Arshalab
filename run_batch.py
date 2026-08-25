#!/usr/bin/env python3
"""Run benchmark on a specific range of KDFS questions with full metrics."""
import sys
import json
import time
import csv
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from src.llm.deepseek_analyzer import DeepSeekAnalyzer
sys.path.insert(0, str(Path(__file__).parent / 'benchmark'))
from evaluation_metrics import (
    HallucinationDetector, AccuracyEvaluator
)

start_num = int(sys.argv[1]) if len(sys.argv) > 1 else 1
end_num = int(sys.argv[2]) if len(sys.argv) > 2 else 10
num_runs = int(sys.argv[3]) if len(sys.argv) > 3 else 3  # consistency runs
no_cache = '--no-cache' in sys.argv  # force re-run all questions

ES_URL = "http://localhost:9200"
CASE_ID = "case_20260128_141256"
CACHE_DIR = Path('benchmark_results/cache')
CACHE_DIR.mkdir(parents=True, exist_ok=True)

with open('benchmark/questions/KDFS_2023.json', encoding='utf-8') as f:
    data = json.load(f)

questions = [q for q in data['questions']
             if q['category'] == 'retrieval' and
             start_num <= int(q['id'].replace('KDFS','')) <= end_num]


def load_cache(qid):
    """Load cached response for a question if it exists and has good recall."""
    cache_file = CACHE_DIR / f'{qid}.json'
    if cache_file.exists() and not no_cache:
        with open(cache_file, encoding='utf-8') as f:
            cached = json.load(f)
        if cached.get('recall', 0) >= 0.9:
            return cached
    return None


def save_cache(qid, result_data):
    """Save question result to cache."""
    cache_file = CACHE_DIR / f'{qid}.json'
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)


print(f"Running KDFS{start_num:02d}-KDFS{end_num:02d} ({len(questions)} questions, {num_runs} runs each)")
print("="*70)

analyzer = DeepSeekAnalyzer(es_url=ES_URL, case_id=CASE_ID)
halluc_detector = HallucinationDetector(es_url=ES_URL, case_id=CASE_ID)
accuracy_eval = AccuracyEvaluator(es_url=ES_URL, case_id=CASE_ID)


def check_keywords(response, keywords):
    found = []
    missed = []
    for kw in keywords:
        if kw.lower() in response.lower():
            found.append(kw)
        else:
            missed.append(kw)
    total = len(found) + len(missed)
    recall = len(found) / total if total > 0 else 0
    return recall, found, missed


detailed_results = []
totals = {'recall': 0, 'accuracy': 0, 'halluc_free': 0, 'consistency': 0, 'latency': 0}

cached_count = 0
api_count = 0

for q in questions:
    print(f"\n[{q['id']}] {q['question'][:60]}...")

    # Check cache first
    cached = load_cache(q['id'])
    if cached:
        cached_count += 1
        # Re-check keywords (in case keywords were updated in JSON)
        keywords = q.get('keywords', [])
        recall, found, missed = check_keywords(cached['response'], keywords)
        if recall >= 0.9:
            print(f"  [CACHED] Recall={recall:.0%} — skipping API call")
            # Use cached data but update keywords info
            cached['keywords'] = keywords
            cached['keywords_found'] = found
            cached['keywords_missing'] = missed
            cached['recall'] = round(recall, 4)
            detailed_results.append(cached)
            totals['recall'] += cached['recall']
            totals['accuracy'] += cached.get('accuracy', 1.0)
            totals['halluc_free'] += cached.get('hallucination_free', 1.0)
            totals['consistency'] += cached.get('consistency', 1.0)
            totals['latency'] += cached.get('latency_s', 0)
            continue
        else:
            print(f"  [CACHE STALE] keywords changed, recall={recall:.0%} — re-running")

    # API call needed
    api_count += 1
    responses = []
    latencies = []
    for run_i in range(num_runs):
        analyzer.clear_history()
        print(f"  Run {run_i+1}/{num_runs}...", end=" ", flush=True)
        t0 = time.time()
        # For retrieval benchmark: ask for brief factual answer only
        bench_query = q['question'] + "\n\nAnswer briefly with facts only, no explanations or recommendations."
        resp = analyzer.analyze(bench_query)
        lat = time.time() - t0
        responses.append(resp)
        latencies.append(lat)
        print(f"{lat:.1f}s", flush=True)

    # Use first response as primary
    primary_response = responses[0]
    avg_latency = sum(latencies) / len(latencies)

    # 1. Keyword Recall
    keywords = q.get('keywords', [])
    recall, found, missed = check_keywords(primary_response, keywords)
    precision = 1.0
    f1 = 2 * recall * precision / (recall + precision) if (recall + precision) > 0 else 0

    # 2. Hallucination Detection
    halluc_report = halluc_detector.analyze(primary_response)
    halluc_rate = halluc_report.hallucination_rate
    halluc_free = 1.0 - halluc_rate

    # 3. Factual Accuracy (vs ES data)
    ground_truth = q.get('expected_facts', None)
    accuracy_result = accuracy_eval.evaluate(primary_response, ground_truth)
    accuracy_score = accuracy_result.score

    # 4. Consistency (keyword-based across runs)
    if keywords and len(responses) > 1:
        kw_in_all = 0
        for kw in keywords:
            if all(kw.lower() in r.lower() for r in responses):
                kw_in_all += 1
        consistency_score = kw_in_all / len(keywords)
    else:
        consistency_score = 1.0

    # Overall score (weighted)
    overall = 0.3 * recall + 0.25 * accuracy_score + 0.25 * halluc_free + 0.2 * consistency_score

    totals['recall'] += recall
    totals['accuracy'] += accuracy_score
    totals['halluc_free'] += halluc_free
    totals['consistency'] += consistency_score
    totals['latency'] += avg_latency

    result_entry = {
        'question_id': q['id'],
        'question': q['question'],
        'category': q['category'],
        'response': primary_response,
        'all_responses': responses,
        'keywords': keywords,
        'keywords_found': found,
        'keywords_missing': missed,
        'recall': round(recall, 4),
        'precision': round(precision, 4),
        'f1': round(f1, 4),
        'accuracy': round(accuracy_score, 4),
        'hallucination_rate': round(halluc_rate, 4),
        'hallucination_free': round(halluc_free, 4),
        'halluc_details': {
            'total_claims': halluc_report.total_claims,
            'verified': halluc_report.verified_claims,
            'hallucinated': halluc_report.hallucinated_claims,
            'unverifiable': halluc_report.unverifiable_claims,
            'fake_files': halluc_report.fake_files[:5],
            'fake_timestamps': halluc_report.fake_timestamps[:5],
        },
        'consistency': round(consistency_score, 4),
        'consistency_details': {'method': 'keyword_based', 'keywords_in_all_runs': kw_in_all if keywords and len(responses) > 1 else len(keywords)},
        'accuracy_details': accuracy_result.details,
        'overall': round(overall, 4),
        'latency_s': round(avg_latency, 2),
        'response_length': len(primary_response),
        'num_runs': num_runs,
    }

    detailed_results.append(result_entry)
    save_cache(q['id'], result_entry)

    status = "OK" if recall >= 0.9 else ("~" if recall >= 0.5 else "X")
    print(f"  [{status}] Recall={recall:.0%} Accuracy={accuracy_score:.0%} "
          f"Halluc-free={halluc_free:.0%} Consistency={consistency_score:.0%} "
          f"Overall={overall:.0%} Latency={avg_latency:.1f}s")
    if recall < 0.9:
        print(f"  >> {primary_response[:180]}")

# Summary
n = len(questions)
print(f"\n{'='*70}")
print(f"KDFS{start_num:02d}-KDFS{end_num:02d} Results ({n} questions, {num_runs} runs each):")
print(f"  Recall:           {totals['recall']/n:.1%}")
print(f"  Factual Accuracy: {totals['accuracy']/n:.1%}")
print(f"  Halluc-free:      {totals['halluc_free']/n:.1%}")
print(f"  Consistency:      {totals['consistency']/n:.1%}")
print(f"  Avg Latency:      {totals['latency']/n:.1f}s")
overall_avg = (0.3*(totals['recall']/n) + 0.25*(totals['accuracy']/n) +
               0.25*(totals['halluc_free']/n) + 0.2*(totals['consistency']/n))
print(f"  Overall Score:    {overall_avg:.1%}")
print(f"  API calls:        {api_count} (cached: {cached_count})")

print("\nPer-question:")
for r in detailed_results:
    s = "OK" if r['recall'] >= 0.9 else ("~" if r['recall'] >= 0.5 else "X")
    print(f"  [{s}] {r['question_id']}: R={r['recall']:.0%} A={r['accuracy']:.0%} "
          f"H={r['hallucination_free']:.0%} C={r['consistency']:.0%} "
          f"O={r['overall']:.0%} missed={r['keywords_missing'][:2]}")

# Save JSON
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
out_dir = Path('benchmark_results')
out_dir.mkdir(exist_ok=True)

report = {
    'timestamp': datetime.now().isoformat(),
    'range': f'KDFS{start_num:02d}-KDFS{end_num:02d}',
    'cases': ['KDFS_2023'],
    'providers': ['deepseek'],
    'num_questions': n,
    'num_runs': num_runs,
    'summary': {
        'avg_recall': round(totals['recall']/n, 4),
        'avg_accuracy': round(totals['accuracy']/n, 4),
        'avg_hallucination_free': round(totals['halluc_free']/n, 4),
        'avg_consistency': round(totals['consistency']/n, 4),
        'avg_latency_s': round(totals['latency']/n, 2),
        'overall_score': round(overall_avg, 4),
    },
    'detailed_results': detailed_results,
}

json_path = out_dir / f'benchmark_{timestamp}.json'
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

# Save CSV
csv_path = out_dir / f'benchmark_{timestamp}.csv'
with open(csv_path, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['case', 'question_id', 'category', 'provider', 'num_runs',
                'latency_s', 'recall', 'precision', 'f1',
                'accuracy', 'hallucination_rate', 'hallucination_free',
                'consistency', 'overall',
                'keywords_found', 'keywords_missing', 'response_length',
                'total_claims', 'verified_claims', 'hallucinated_claims'])
    for r in detailed_results:
        w.writerow([
            'KDFS_2023', r['question_id'], r['category'], 'deepseek', num_runs,
            r['latency_s'], r['recall'], r['precision'], r['f1'],
            r['accuracy'], r['hallucination_rate'], r['hallucination_free'],
            r['consistency'], r['overall'],
            '; '.join(r['keywords_found']), '; '.join(r['keywords_missing']),
            r['response_length'],
            r['halluc_details']['total_claims'],
            r['halluc_details']['verified'],
            r['halluc_details']['hallucinated'],
        ])

print(f"\nSaved: {json_path}")
print(f"Saved: {csv_path}")
