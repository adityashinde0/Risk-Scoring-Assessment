"""Command-line interface to execute P-006 risk assessment on any local event file."""

import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.pipeline import export_assessment_to_files, run_assessment_pipeline


def main():
    parser = argparse.ArgumentParser(description="P-006 Predictive Risk Scoring Assessment CLI")
    parser.add_argument("--file", "-f", type=str, default="backend/data/security_events.json", help="Path to input CSV or JSON events file")
    parser.add_argument("--output-dir", "-o", type=str, default="backend/output", help="Directory to save assessment artifacts")
    parser.add_argument("--seed", "-s", type=int, default=42, help="Deterministic seed for Random Selection and Isolation Forest")
    parser.add_argument("--rule-weight", "-rw", type=float, default=0.60, help="Weight for explainable rule score (0.0 - 1.0)")
    parser.add_argument("--anomaly-weight", "-aw", type=float, default=0.40, help="Weight for Isolation Forest anomaly score (0.0 - 1.0)")
    parser.add_argument("--review-rate", "-r", type=float, default=0.25, help="Review selection rate for Random Selection baseline")

    args = parser.parse_args()

    input_file = Path(args.file)
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    print(f"[*] Running P-006 Risk Assessment on: {input_file} (seed={args.seed})")
    result = run_assessment_pipeline(
        file_path=input_file,
        rule_weight=args.rule_weight,
        anomaly_weight=args.anomaly_weight,
        random_seed=args.seed,
        baseline_review_rate=args.review_rate,
    )

    print("\n" + "=" * 60)
    print(f"Assessment Run ID: {result.run_id}")
    print(f"Entities Scored:   {result.total_entities_evaluated}")
    print(f"Risk Bands:        {result.risk_band_counts}")
    print(f"Model Status:      {result.model_status}")
    print(f"Validation:        Valid={result.validation_summary.valid_rows_count}, Quarantined={result.validation_summary.quarantined_rows_count}")
    print("=" * 60)

    print("\n--- TOP RANKED ENTITIES ---")
    print(f"{'Entity ID':<18} {'Type':<12} {'Risk Score (5-50)':<20} {'Band':<10} {'Random Base?':<12} {'Top Contributor'}")
    print("-" * 100)

    for e in result.entities[:10]:
        top_c = e.top_contributors[0].rule_name if e.top_contributors else "None (Statistical anomaly)"
        print(f"{e.entity_id:<18} {e.entity_type:<12} {e.risk_score:<20.2f} {e.risk_band:<10} {str(e.selected_by_random_baseline):<12} {top_c}")

    json_p, csv_p = export_assessment_to_files(result, args.output_dir)
    print(f"\n[+] Exported artifacts:\n  -> JSON: {json_p}\n  -> CSV:  {csv_p}")


if __name__ == "__main__":
    main()
