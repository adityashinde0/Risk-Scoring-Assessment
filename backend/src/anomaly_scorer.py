"""Isolation Forest anomaly scoring module with fallback protection."""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .feature_builder import FEATURE_COLUMNS


class AnomalyScoringResult:
    def __init__(
        self,
        scores_by_entity: Dict[str, float],
        raw_scores_by_entity: Dict[str, float],
        model_status: str,
        warnings: List[str],
        feature_importance_approx: Dict[str, float],
    ):
        self.scores_by_entity = scores_by_entity
        self.raw_scores_by_entity = raw_scores_by_entity
        self.model_status = model_status  # FIT_SUCCESS, FALLBACK_RULE_ONLY
        self.warnings = warnings
        self.feature_importance_approx = feature_importance_approx


def compute_isolation_forest_scores(
    features_df: pd.DataFrame,
    contamination: float = 0.15,
    n_estimators: int = 100,
    random_state: int = 42,
    min_entities_to_fit: int = 3,
) -> AnomalyScoringResult:
    """
    Fit Isolation Forest on entity behavioral features and produce normalized anomaly scores [0, 1].
    Higher value indicates higher anomaly.
    """
    if features_df.empty or len(features_df) < min_entities_to_fit:
        return AnomalyScoringResult(
            scores_by_entity={e: 0.0 for e in features_df["entity_id"]} if not features_df.empty else {},
            raw_scores_by_entity={},
            model_status="FALLBACK_RULE_ONLY",
            warnings=[f"Entity count ({len(features_df)}) below minimum required ({min_entities_to_fit}) to train Isolation Forest. Using rule-only fallback."],
            feature_importance_approx={},
        )

    entity_ids = features_df["entity_id"].tolist()
    X = features_df[FEATURE_COLUMNS].copy().fillna(0.0).to_numpy()

    # Handle zero variance across all features
    if np.all(X == X[0, :]):
        return AnomalyScoringResult(
            scores_by_entity={e: 0.0 for e in entity_ids},
            raw_scores_by_entity={e: 0.0 for e in entity_ids},
            model_status="FALLBACK_RULE_ONLY",
            warnings=["All entities have identical feature vectors; zero variance. Using rule-only fallback."],
            feature_importance_approx={},
        )

    try:
        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=1,
        )
        model.fit(X)

        # decision_function: lower/negative = more anomalous.
        # score_samples: opposite of anomaly score.
        raw_decisions = model.decision_function(X)  # e.g., range typically -0.3 to +0.3

        # Invert so higher = more anomalous
        inverted = -raw_decisions
        min_v, max_v = np.min(inverted), np.max(inverted)

        # Min-max normalization to [0.0, 1.0]
        if max_v > min_v:
            norm_scores = (inverted - min_v) / (max_v - min_v)
        else:
            norm_scores = np.zeros_like(inverted)

        scores_by_entity = {entity_ids[i]: round(float(norm_scores[i]), 4) for i in range(len(entity_ids))}
        raw_scores_by_entity = {entity_ids[i]: round(float(raw_decisions[i]), 4) for i in range(len(entity_ids))}

        # Approximate feature variance contribution as proxy explanation
        stds = np.std(X, axis=0)
        total_std = np.sum(stds)
        importance = {}
        if total_std > 0:
            for idx, col in enumerate(FEATURE_COLUMNS):
                importance[col] = round(float(stds[idx] / total_std), 4)

        return AnomalyScoringResult(
            scores_by_entity=scores_by_entity,
            raw_scores_by_entity=raw_scores_by_entity,
            model_status="FIT_SUCCESS",
            warnings=[],
            feature_importance_approx=importance,
        )

    except Exception as e:
        return AnomalyScoringResult(
            scores_by_entity={e: 0.0 for e in entity_ids},
            raw_scores_by_entity={},
            model_status="FALLBACK_RULE_ONLY",
            warnings=[f"Isolation Forest fitting encountered error: {str(e)}. Falling back to rule-only score."],
            feature_importance_approx={},
        )
