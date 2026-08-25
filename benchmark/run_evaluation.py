# benchmark/run_evaluation.py
"""
Run comprehensive evaluation: accuracy, consistency, hallucination detection.
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmark.evaluation_metrics import ForensicEvaluator, HallucinationDetector


def load_benchmark_questions(case_name: str) -> List[Dict]:
    """Load benchmark questions for a case."""
    questions_file = Path(__file__).parent / "questions" / f"{case_name}.json"

    if questions_file.exists():
        with open(questions_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    # Default questions if no case-specific file
    return [
        {"id": "Q01", "question": "What is the primary user account on this system?"},
        {"id": "Q02", "question": "What suspicious executables were run from temporary folders?"},
        {"id": "Q03", "question": "What files were deleted and when?"},
        {"id": "Q04", "question": "What persistence mechanisms are present?"},
        {"id": "Q05", "question": "What network activity is suspicious?"},
    ]


def run_consistency_test(analyzer, question: str, num_runs: int = 3) -> List[str]:
    """Run same question multiple times to test consistency."""
    responses = []

    for i in range(num_runs):
        print(f"    Run {i+1}/{num_runs}...", end=" ", flush=True)
        # Clear history for independent runs
        analyzer.clear_history()
        response = analyzer.analyze(question)
        responses.append(response)
        print("done")

    return responses


def evaluate_provider(provider_name: str, case_id: str,
                     questions: List[Dict], consistency_runs: int = 3,
                     es_url: str = "http://localhost:9200") -> Dict:
    """
    Evaluate a single provider on all metrics.

    Args:
        provider_name: "claude", "opus", "deepseek", etc.
        case_id: Case ID in Elasticsearch
        questions: List of questions to evaluate
        consistency_runs: Number of runs per question for consistency test
        es_url: Elasticsearch URL

    Returns:
        Evaluation results dict
    """
    # Initialize analyzer
    if provider_name == "claude":
        from src.llm.claude_analyzer import ClaudeAnalyzer
        analyzer = ClaudeAnalyzer(es_url=es_url, case_id=case_id)
    elif provider_name == "opus":
        from src.llm.opus_analyzer import OpusAnalyzer
        analyzer = OpusAnalyzer(es_url=es_url, case_id=case_id)
    elif provider_name == "deepseek":
        from src.llm.deepseek_analyzer import DeepSeekAnalyzer
        analyzer = DeepSeekAnalyzer(es_url=es_url, case_id=case_id)
    else:
        raise ValueError(f"Unknown provider: {provider_name}")

    evaluator = ForensicEvaluator(es_url=es_url, case_id=case_id)

    results = {
        "provider": provider_name,
        "case_id": case_id,
        "timestamp": datetime.now().isoformat(),
        "num_questions": len(questions),
        "consistency_runs": consistency_runs,
        "questions": []
    }

    total_accuracy = 0
    total_hallucination_free = 0
    total_consistency = 0

    for q in questions:
        print(f"\n  [{q['id']}] {q['question'][:50]}...")

        # Run consistency test (multiple runs of same question)
        responses = run_consistency_test(analyzer, q["question"], consistency_runs)

        # Get ground truth if available
        ground_truth = q.get("expected_facts", None)

        # Full evaluation
        eval_result = evaluator.full_evaluation(
            question=q["question"],
            responses=responses,
            ground_truth=ground_truth
        )

        # Store results
        q_result = {
            "id": q["id"],
            "question": q["question"],
            "accuracy": eval_result["metrics"]["accuracy"]["mean"],
            "hallucination_free": eval_result["metrics"]["hallucination_free"]["mean"],
            "consistency": eval_result["metrics"]["consistency"]["score"],
            "overall": eval_result["overall_score"],
            "details": eval_result
        }

        results["questions"].append(q_result)

        # Accumulate totals
        total_accuracy += q_result["accuracy"]
        total_hallucination_free += q_result["hallucination_free"]
        total_consistency += q_result["consistency"]

        print(f"    Accuracy: {q_result['accuracy']:.2f} | "
              f"Halluc-free: {q_result['hallucination_free']:.2f} | "
              f"Consistency: {q_result['consistency']:.2f}")

    # Calculate averages
    n = len(questions)
    results["summary"] = {
        "avg_accuracy": total_accuracy / n,
        "avg_hallucination_free": total_hallucination_free / n,
        "avg_consistency": total_consistency / n,
        "overall_score": (
            0.4 * (total_accuracy / n) +
            0.3 * (total_hallucination_free / n) +
            0.3 * (total_consistency / n)
        )
    }

    return results


def run_full_evaluation(cases: List[str], providers: List[str],
                       consistency_runs: int = 3,
                       output_dir: str = "benchmark/results") -> Dict:
    """
    Run full evaluation across all cases and providers.

    Args:
        cases: List of case IDs
        providers: List of provider names
        consistency_runs: Number of runs per question
        output_dir: Output directory for results

    Returns:
        Complete evaluation results
    """
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print("FORENSIC AI EVALUATION")
    print("=" * 70)
    print(f"Cases: {', '.join(cases)}")
    print(f"Providers: {', '.join(providers)}")
    print(f"Consistency runs: {consistency_runs}")
    print("=" * 70)

    all_results = {
        "timestamp": datetime.now().isoformat(),
        "cases": cases,
        "providers": providers,
        "consistency_runs": consistency_runs,
        "evaluations": []
    }

    for case_id in cases:
        print(f"\n*** Case: {case_id} ***")

        # Load questions
        questions = load_benchmark_questions(case_id)
        print(f"  Questions: {len(questions)}")

        for provider in providers:
            print(f"\n  === {provider.upper()} ===")

            try:
                result = evaluate_provider(
                    provider_name=provider,
                    case_id=case_id,
                    questions=questions,
                    consistency_runs=consistency_runs
                )
                all_results["evaluations"].append(result)

                print(f"\n  Summary for {provider}:")
                print(f"    Accuracy:         {result['summary']['avg_accuracy']:.2%}")
                print(f"    Hallucination-free: {result['summary']['avg_hallucination_free']:.2%}")
                print(f"    Consistency:      {result['summary']['avg_consistency']:.2%}")
                print(f"    Overall:          {result['summary']['overall_score']:.2%}")

            except Exception as e:
                print(f"  [ERROR] {provider}: {e}")
                all_results["evaluations"].append({
                    "provider": provider,
                    "case_id": case_id,
                    "error": str(e)
                })

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = Path(output_dir) / f"evaluation_{timestamp}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 70}")
    print(f"Results saved to: {output_file}")

    # Print comparison table
    print_comparison_table(all_results)

    return all_results


def print_comparison_table(results: Dict):
    """Print comparison table of all evaluations."""
    print("\n" + "=" * 70)
    print("COMPARISON TABLE")
    print("=" * 70)

    # Header
    print(f"{'Provider':<15} {'Case':<20} {'Accuracy':>10} {'NoHalluc':>10} {'Consist':>10} {'Overall':>10}")
    print("-" * 75)

    for eval_result in results["evaluations"]:
        if "error" in eval_result:
            print(f"{eval_result['provider']:<15} {eval_result['case_id']:<20} {'ERROR':>10}")
            continue

        summary = eval_result["summary"]
        print(f"{eval_result['provider']:<15} "
              f"{eval_result['case_id']:<20} "
              f"{summary['avg_accuracy']:>9.1%} "
              f"{summary['avg_hallucination_free']:>9.1%} "
              f"{summary['avg_consistency']:>9.1%} "
              f"{summary['overall_score']:>9.1%}")

    print("=" * 70)


def quick_hallucination_test(provider: str, case_id: str, question: str):
    """Quick test to check hallucination detection."""
    print(f"\nQuick Hallucination Test")
    print(f"Provider: {provider}")
    print(f"Case: {case_id}")
    print(f"Question: {question}")
    print("-" * 50)

    # Get response
    if provider == "claude":
        from src.llm.claude_analyzer import ClaudeAnalyzer
        analyzer = ClaudeAnalyzer(case_id=case_id)
    elif provider == "deepseek":
        from src.llm.deepseek_analyzer import DeepSeekAnalyzer
        analyzer = DeepSeekAnalyzer(case_id=case_id)
    else:
        print(f"Unknown provider: {provider}")
        return

    print("\nGetting response...")
    response = analyzer.analyze(question)

    print(f"\nResponse ({len(response)} chars):")
    print(response[:500] + "..." if len(response) > 500 else response)

    # Analyze for hallucinations
    print("\n" + "-" * 50)
    print("Hallucination Analysis:")

    detector = HallucinationDetector(case_id=case_id)
    report = detector.analyze(response)

    print(f"  Total claims: {report.total_claims}")
    print(f"  Verified: {report.verified_claims}")
    print(f"  Hallucinated: {report.hallucinated_claims}")
    print(f"  Unverifiable: {report.unverifiable_claims}")
    print(f"  Hallucination rate: {report.hallucination_rate:.1%}")

    if report.fake_files:
        print(f"\n  Fake files: {report.fake_files[:5]}")
    if report.fake_timestamps:
        print(f"  Fake timestamps: {report.fake_timestamps[:5]}")
    if report.fake_events:
        print(f"  Fake events: {report.fake_events[:5]}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run forensic AI evaluation")
    parser.add_argument("--cases", nargs="+", default=["CTF_Magnet_2022"],
                       help="Case IDs to evaluate")
    parser.add_argument("--providers", nargs="+", default=["claude"],
                       help="Providers to evaluate")
    parser.add_argument("--runs", type=int, default=3,
                       help="Number of runs per question for consistency")
    parser.add_argument("--quick", action="store_true",
                       help="Quick hallucination test mode")
    parser.add_argument("--question", type=str,
                       help="Question for quick test")

    args = parser.parse_args()

    if args.quick:
        question = args.question or "What suspicious programs were executed?"
        quick_hallucination_test(args.providers[0], args.cases[0], question)
    else:
        run_full_evaluation(
            cases=args.cases,
            providers=args.providers,
            consistency_runs=args.runs
        )
