"""Evaluation module comparing Random Selection baseline, Rule-Only, Isolation Forest, and Combined scoring."""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set
import numpy as np
from pydantic import BaseModel, Field

from .schema import AssessmentOutput, EntityAssessmentResult


class MethodEvaluationMetrics(BaseModel):
    method_name: str
    description: str
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    top_k_threat_capture_rate: float
    prioritized_entities: List[str]


class BenchmarkEvaluationReport(BaseModel):
    dataset_type: str = "Synthetic Insider Threat Scenario (Demo)"
    is_synthetic_benchmark: bool = True
    disclaimer: str = (
        "Evaluation results are measured strictly against labeled synthetic insider threat demo scenarios. "
        "These metrics demonstrate comparative algorithmic lift over random review and individual signals under controlled conditions; "
        "they must not be claimed as unverified real-world production cybersecurity accuracy."
    )
    total_entities: int
    ground_truth_threat_count: int
    ground_truth_threat_entities: List[str]
    methods: List[MethodEvaluationMetrics]
    comparative_summary: str


# Standard ground-truth threat labels defined in the demo dataset
DEMO_GROUND_TRUTH_THREATS: Set[str] = {
    "user_jdoe",        # Compromised credential / odd-hour brute force
    "admin_mscott",     # Rogue admin privilege escalation & audit disable
    "dev_alice",        # Data exfiltration burst
    "service_backup",   # Firewall port scan / probe
}


def _calculate_classification_metrics(
    selected_entities: List[str],
    all_entities: List[str],
    ground_truth: Set[str],
    method_name: str,
    description: str,
) -> MethodEvaluationMetrics:
    """Compute standard classification and ranking metrics."""
    selected_set = set(selected_entities)
    all_set = set(all_entities)
    total_positives = len(ground_truth)
    total_negatives = len(all_set - ground_truth)

    tp = len(selected_set.intersection(ground_truth))
    fp = len(selected_set - ground_truth)
    fn = len(ground_truth - selected_set)
    tn = len((all_set - selected_set) - ground_truth)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / total_positives if total_positives > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / total_negatives if total_negatives > 0 else 0.0
    top_k_capture = tp / total_positives if total_positives > 0 else 0.0

    return MethodEvaluationMetrics(
        method_name=method_name,
        description=description,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        top_k_threat_capture_rate=round(top_k_capture, 4),
        prioritized_entities=sorted(list(selected_set)),
    )


def evaluate_assessment_methods(
    assessment: AssessmentOutput,
    ground_truth_threats: Optional[Set[str]] = None,
) -> BenchmarkEvaluationReport:
    """
    Evaluate and compare:
    1. Random Selection baseline (fixed seed)
    2. Rule-Only prioritization (rule_score >= threshold)
    3. Isolation Forest anomaly scoring (top k by anomaly_score)
    4. Combined dynamic risk scoring (risk_band in ['high', 'critical'] or risk_score >= 30.0)
    """
    if ground_truth_threats is None:
        ground_truth_threats = DEMO_GROUND_TRUTH_THREATS

    all_entities = [e.entity_id for e in assessment.entities]
    k_targets = len(ground_truth_threats)

    # 1. Random Selection Baseline Candidates
    random_candidates = assessment.baseline_comparison.random_baseline_selected

    # 2. Rule-Only Candidates (Entities with rule_score >= 8.0)
    rule_sorted = sorted(assessment.entities, key=lambda x: x.rule_score, reverse=True)
    rule_candidates = [e.entity_id for e in rule_sorted if e.rule_score >= 8.0]
    if not rule_candidates and rule_sorted:
        rule_candidates = [e.entity_id for e in rule_sorted[:k_targets]]

    # 3. Isolation Forest Candidates (Top-k by anomaly score)
    if_sorted = sorted(assessment.entities, key=lambda x: (x.anomaly_score or 0.0), reverse=True)
    if_candidates = [e.entity_id for e in if_sorted[:max(k_targets, len(random_candidates))]]

    # 4. Combined Dynamic Risk Candidates (High/Critical or top-k)
    combined_candidates = [e.entity_id for e in assessment.entities if e.risk_band in ["high", "critical"] or e.risk_score >= 30.0]
    if not combined_candidates and assessment.entities:
        combined_candidates = [e.entity_id for e in assessment.entities[:k_targets]]

    # Compute metrics for all 4 approaches
    m_random = _calculate_classification_metrics(
        random_candidates, all_entities, ground_truth_threats,
        "Random Selection Baseline",
        f"Chance-level control selecting entities at random (seed={assessment.baseline_comparison.seed}, review_rate={assessment.baseline_comparison.review_rate:.0%})."
    )

    m_rule = _calculate_classification_metrics(
        rule_candidates, all_entities, ground_truth_threats,
        "Rule-Only Signal Engine",
        "Deterministic domain indicators without statistical anomaly weighting."
    )

    m_if = _calculate_classification_metrics(
        if_candidates, all_entities, ground_truth_threats,
        "Isolation Forest ML",
        "Unsupervised multivariate anomaly detection isolated from explicit rule triggers."
    )

    m_combined = _calculate_classification_metrics(
        combined_candidates, all_entities, ground_truth_threats,
        "Combined Dynamic Risk Scoring (P-006 System)",
        "Blended model combining Isolation Forest anomaly percentiles and domain rule severity normalized to 5-50 scale."
    )

    summary = (
        f"On the labeled scenario dataset ({len(all_entities)} entities, {len(ground_truth_threats)} ground-truth threats), "
        f"the Combined Scoring system achieved F1={m_combined.f1_score:.2f} (Recall: {m_combined.recall:.0%}, Precision: {m_combined.precision:.0%}) "
        f"compared to Random Selection baseline F1={m_random.f1_score:.2f} (Recall: {m_random.recall:.0%}, Precision: {m_random.precision:.0%}). "
        f"Isolation Forest alone achieved F1={m_if.f1_score:.2f} and Rule-only achieved F1={m_rule.f1_score:.2f}."
    )

    return BenchmarkEvaluationReport(
        dataset_type="Synthetic Insider Threat Scenario (Demo)",
        is_synthetic_benchmark=True,
        total_entities=len(all_entities),
        ground_truth_threat_count=len(ground_truth_threats),
        ground_truth_threat_entities=sorted(list(ground_truth_threats)),
        methods=[m_combined, m_rule, m_if, m_random],
        comparative_summary=summary,
    )
