"""Risk score normalization, bounded mapping (5.0 - 50.0), and band assignment."""

from __future__ import annotations
from typing import Dict, Tuple


def calculate_normalized_risk_score(
    rule_score: float,
    anomaly_score: float,
    rule_weight: float = 0.60,
    anomaly_weight: float = 0.40,
    rule_score_cap: float = 35.0,
) -> Tuple[float, str]:
    """
    Combines explainable rule score and Isolation Forest anomaly score into
    a strictly bounded dynamic risk score between 5.0 and 50.0.

    Returns:
        (risk_score, risk_band)
    """
    # Normalize weights
    total_w = rule_weight + anomaly_weight
    if total_w > 0:
        w_rule = rule_weight / total_w
        w_anom = anomaly_weight / total_w
    else:
        w_rule = 0.5
        w_anom = 0.5

    # Scale rule score to [0.0, 1.0]
    scaled_rule = min(1.0, max(0.0, rule_score / max(1.0, rule_score_cap)))

    # Anomaly score is already in [0.0, 1.0]
    scaled_anom = min(1.0, max(0.0, anomaly_score))

    # Blended risk intensity [0.0, 1.0]
    blended_intensity = (w_rule * scaled_rule) + (w_anom * scaled_anom)

    # Map to strict range [5.0, 50.0]
    calculated_score = 5.0 + (blended_intensity * 45.0)

    # Enforce hard engineering invariant clamp
    final_score = round(min(50.0, max(5.0, calculated_score)), 2)

    # Classify into risk band
    if final_score < 15.0:
        band = "low"
    elif final_score < 30.0:
        band = "medium"
    elif final_score < 42.0:
        band = "high"
    else:
        band = "critical"

    return final_score, band
