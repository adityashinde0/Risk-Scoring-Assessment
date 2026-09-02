"""End-to-end assessment pipeline orchestrator for P-006 Predictive Risk Scoring."""

from __future__ import annotations
import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import pandas as pd

from .anomaly_scorer import compute_isolation_forest_scores
from .baseline import generate_random_baseline
from .evaluation import evaluate_assessment_methods
from .feature_builder import build_entity_features
from .ingestion import ingest_records, load_and_ingest_file
from .recommendations import generate_recommendations
from .risk_normalizer import calculate_normalized_risk_score
from .rule_engine import compute_all_rule_scores
from .schema import (
    AssessmentOutput,
    EntityAssessmentResult,
    ValidationSummary,
)


def run_assessment_pipeline(
    records: Optional[List[Dict[str, Any]]] = None,
    file_path: Optional[Union[str, Path]] = None,
    rule_weight: float = 0.60,
    anomaly_weight: float = 0.40,
    random_seed: int = 42,
    baseline_review_rate: float = 0.25,
    contamination: float = 0.15,
    n_estimators: int = 100,
    window_id: str = "window_2_threats",
    baseline_history_file: Optional[Union[str, Path]] = None,
) -> AssessmentOutput:
    """
    Execute full assessment pipeline on event records or local file.
    Produces schema-compliant AssessmentOutput object with evaluation benchmarks and score deltas.
    """
    run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    generated_at = datetime.now(timezone.utc).isoformat()

    # Step 1: Ingestion & Schema Validation
    if file_path is not None:
        valid_df, val_summary = load_and_ingest_file(file_path)
    elif records is not None:
        valid_df, val_summary = ingest_records(records)
    else:
        raise ValueError("Either 'records' or 'file_path' must be provided.")

    if valid_df.empty:
        # Graceful empty response
        empty_baseline = generate_random_baseline([], [], baseline_review_rate, random_seed)
        return AssessmentOutput(
            run_id=run_id,
            window_id=window_id,
            generated_at=generated_at,
            total_entities_evaluated=0,
            risk_band_counts={"low": 0, "medium": 0, "high": 0, "critical": 0},
            entities=[],
            baseline_comparison=empty_baseline,
            validation_summary=val_summary,
            scoring_config={
                "rule_weight": rule_weight,
                "anomaly_weight": anomaly_weight,
                "random_seed": random_seed,
                "baseline_review_rate": baseline_review_rate,
                "contamination": contamination,
            },
            model_status="FALLBACK_RULE_ONLY",
            evaluation_benchmark=None,
        )

    # Historical baseline comparison for dynamic adaptation demonstration
    prev_scores_map: Dict[str, float] = {}
    if baseline_history_file is not None and Path(baseline_history_file).exists():
        try:
            prev_df, _ = load_and_ingest_file(baseline_history_file)
            if not prev_df.empty:
                prev_feat_df, _ = build_entity_features(prev_df)
                prev_rules = compute_all_rule_scores(prev_feat_df)
                prev_anom = compute_isolation_forest_scores(
                    prev_feat_df, contamination=contamination, n_estimators=50, random_state=random_seed
                )
                for _, prow in prev_feat_df.iterrows():
                    pe_id = str(prow["entity_id"])
                    pr_score, _ = prev_rules.get(pe_id, (0.0, []))
                    pa_score = prev_anom.scores_by_entity.get(pe_id, 0.0)
                    pf_score, _ = calculate_normalized_risk_score(pr_score, pa_score, rule_weight, anomaly_weight)
                    prev_scores_map[pe_id] = pf_score
        except Exception:
            prev_scores_map = {}

    # Step 2: Feature Aggregation
    features_df, entity_type_map = build_entity_features(valid_df)

    # Step 3: Rule / Pattern Signal Engine
    rule_results = compute_all_rule_scores(features_df)

    # Step 4: Isolation Forest Anomaly Scorer
    anomaly_res = compute_isolation_forest_scores(
        features_df=features_df,
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_seed,
    )

    # Step 5: Score Normalization (5.0 - 50.0) & Recommendations
    entities_results: List[EntityAssessmentResult] = []
    band_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    ml_high_risk_entities: List[str] = []

    for _, row in features_df.iterrows():
        entity_id = str(row["entity_id"])
        rule_score, contributors = rule_results.get(entity_id, (0.0, []))
        norm_anomaly = anomaly_res.scores_by_entity.get(entity_id, 0.0)
        raw_anomaly = anomaly_res.raw_scores_by_entity.get(entity_id, None)

        final_score, risk_band = calculate_normalized_risk_score(
            rule_score=rule_score,
            anomaly_score=norm_anomaly,
            rule_weight=rule_weight,
            anomaly_weight=anomaly_weight,
        )

        band_counts[risk_band] = band_counts.get(risk_band, 0) + 1

        if risk_band in ["high", "critical"] or final_score >= 30.0:
            ml_high_risk_entities.append(entity_id)

        recommendations = generate_recommendations(
            entity_id=entity_id,
            risk_score=final_score,
            risk_band=risk_band,
            contributors=contributors,
        )

        # Compute dynamic change metrics
        prev_score = prev_scores_map.get(entity_id)
        delta = round(final_score - prev_score, 2) if prev_score is not None else None
        if delta is not None:
            trend = "ESCALATED" if delta >= 5.0 else ("REDUCED" if delta <= -5.0 else "STABLE")
        else:
            trend = "STABLE"

        # Feature summary for analyst inspection
        feat_dict = {
            "total_events": int(row.get("total_events", 0)),
            "login_count": int(row.get("login_count", 0)),
            "failed_login_count": int(row.get("failed_login_count", 0)),
            "failed_login_ratio": round(float(row.get("failed_login_ratio", 0)), 2),
            "odd_hour_count": int(row.get("odd_hour_count", 0)),
            "distinct_source_ips": int(row.get("distinct_source_ips", 0)),
            "distinct_resources": int(row.get("distinct_resources", 0)),
            "privilege_change_count": int(row.get("privilege_change_count", 0)),
            "config_change_count": int(row.get("config_change_count", 0)),
            "firewall_denied_count": int(row.get("firewall_denied_count", 0)),
            "total_bytes_mb": round(float(row.get("total_bytes_transferred", 0)) / (1024 * 1024), 2),
        }

        entity_res = EntityAssessmentResult(
            entity_id=entity_id,
            entity_type=entity_type_map.get(entity_id, "user"),
            risk_score=final_score,
            risk_band=risk_band,
            previous_risk_score=prev_score,
            score_delta=delta,
            trend_status=trend,
            anomaly_score=norm_anomaly,
            raw_anomaly_score=raw_anomaly,
            rule_score=rule_score,
            top_contributors=contributors,
            recommendations=recommendations,
            selected_by_random_baseline=False,  # updated in Step 6
            validation_warnings=anomaly_res.warnings if anomaly_res.warnings else [],
            feature_summary=feat_dict,
        )
        entities_results.append(entity_res)

    # Step 6: Random Selection Baseline & Comparison
    all_entity_ids = [e.entity_id for e in entities_results]
    baseline_metrics = generate_random_baseline(
        all_entity_ids=all_entity_ids,
        ml_high_risk_entities=ml_high_risk_entities,
        review_rate=baseline_review_rate,
        seed=random_seed,
    )

    baseline_set = set(baseline_metrics.random_baseline_selected)
    for e in entities_results:
        if e.entity_id in baseline_set:
            e.selected_by_random_baseline = True

    # Sort entities by risk_score descending
    entities_results.sort(key=lambda x: x.risk_score, reverse=True)

    output = AssessmentOutput(
        run_id=run_id,
        window_id=window_id,
        generated_at=generated_at,
        total_entities_evaluated=len(entities_results),
        risk_band_counts=band_counts,
        entities=entities_results,
        baseline_comparison=baseline_metrics,
        validation_summary=val_summary,
        scoring_config={
            "rule_weight": rule_weight,
            "anomaly_weight": anomaly_weight,
            "random_seed": random_seed,
            "baseline_review_rate": baseline_review_rate,
            "contamination": contamination,
        },
        model_status=anomaly_res.model_status,
    )

    # Step 7: Calculate Multi-Method Evaluation Benchmark
    try:
        eval_report = evaluate_assessment_methods(output)
        output.evaluation_benchmark = eval_report.model_dump()
    except Exception:
        output.evaluation_benchmark = None

    return output


def export_assessment_to_files(assessment: AssessmentOutput, output_dir: Union[str, Path]) -> Tuple[Path, Path]:
    """Export assessment output to JSON and CSV artifacts for audit and reporting."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_file = out_path / f"assessment_{assessment.run_id}.json"
    csv_file = out_path / f"assessment_{assessment.run_id}.csv"

    # Export JSON
    with open(json_file, "w", encoding="utf-8") as f:
        f.write(assessment.model_dump_json(indent=2))

    # Export CSV summary
    csv_rows = []
    for e in assessment.entities:
        contributors_summary = "; ".join([f"{c.rule_name} (+{c.score_contribution})" for c in e.top_contributors])
        recs_summary = "; ".join([r.title for r in e.recommendations])
        csv_rows.append({
            "run_id": assessment.run_id,
            "generated_at": assessment.generated_at,
            "entity_id": e.entity_id,
            "entity_type": e.entity_type,
            "risk_score": e.risk_score,
            "risk_band": e.risk_band,
            "score_delta": e.score_delta,
            "trend_status": e.trend_status,
            "anomaly_score": e.anomaly_score,
            "rule_score": e.rule_score,
            "selected_by_random_baseline": e.selected_by_random_baseline,
            "top_contributors": contributors_summary,
            "recommendations": recs_summary,
        })

    pd.DataFrame(csv_rows).to_csv(csv_file, index=False)

    return json_file, csv_file
