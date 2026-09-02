"""Command-line benchmark evaluation runner comparing Random Selection, Rule-Only, Isolation Forest, and Combined scoring."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from src.evaluation import evaluate_assessment_methods, DEMO_GROUND_TRUTH_THREATS
from src.pipeline import run_assessment_pipeline


def run_benchmark(file_path: Path, random_seed: int = 42, review_rate: float = 0.25):
    print("=" * 80)
    print("  P-006 PREDICTIVE RISK SCORING ASSESSMENT: 4-METHOD BENCHMARK EVALUATION")
    print("=" * 80)
    print(f"[*] Target Dataset:        {file_path}")
    print(f"[*] Ground Truth Threats:  {sorted(list(DEMO_GROUND_TRUTH_THREATS))}")
    print(f"[*] Deterministic Seed:    {random_seed}")
    print(f"[*] Baseline Review Rate:  {review_rate:.0%}\n")

    assessment = run_assessment_pipeline(
        file_path=file_path,
        random_seed=random_seed,
        baseline_review_rate=review_rate,
    )

    report = evaluate_assessment_methods(assessment)

    print("+" + "-" * 78 + "+")
    print(f"| {'EVALUATION DISCLAIMER':<76} |")
    print("+" + "-" * 78 + "+")
    for line in [report.disclaimer[i:i+74] for i in range(0, len(report.disclaimer), 74)]:
        print(f"| {line:<76} |")
    print("+" + "-" * 78 + "+\n")

    print(f"{'Method':<35} {'Precision':<10} {'Recall':<10} {'F1':<8} {'FPR':<10} {'Threat Capture'}")
    print("-" * 80)

    for m in report.methods:
        print(f"{m.method_name:<35} {m.precision * 100:>8.1f}%  {m.recall * 100:>8.1f}%  {m.f1_score:>6.2f}  {m.false_positive_rate * 100:>8.1f}%  {m.top_k_threat_capture_rate * 100:>12.1f}%")

    print("-" * 80)
    print(f"\n[+] Summary Analysis:\n{report.comparative_summary}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P-006 Multi-Method Benchmark Runner")
    parser.add_argument("--file", "-f", type=str, default="backend/data/security_events.json")
    parser.add_argument("--seed", "-s", type=int, default=42)
    parser.add_argument("--review-rate", "-r", type=float, default=0.25)
    args = parser.parse_args()

    run_benchmark(Path(args.file), random_seed=args.seed, review_rate=args.review_rate)
