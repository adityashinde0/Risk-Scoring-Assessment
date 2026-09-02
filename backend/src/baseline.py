"""Random Selection baseline generator and comparative metrics."""

from __future__ import annotations
import random
from typing import List, Set
from .schema import BaselineComparisonMetrics


def generate_random_baseline(
    all_entity_ids: List[str],
    ml_high_risk_entities: List[str],
    review_rate: float = 0.25,
    seed: int = 42,
) -> BaselineComparisonMetrics:
    """
    Select candidate review entities at random using a deterministic seed.
    Compare overlap against ML-flagged high/critical risk entities.
    """
    sorted_entities = sorted(list(set(all_entity_ids)))
    total = len(sorted_entities)

    if total == 0:
        return BaselineComparisonMetrics(
            seed=seed,
            review_rate=review_rate,
            total_entities=0,
            baseline_selected_count=0,
            ml_high_risk_count=0,
            overlap_count=0,
            overlap_ratio=0.0,
            overlap_entities=[],
            isolation_forest_selected=[],
            random_baseline_selected=[],
            explanation="No entities available for baseline comparison.",
        )

    # Determine selection size k
    k = max(1, int(round(total * review_rate)))
    k = min(k, total)

    rng = random.Random(seed)
    selected_baseline = rng.sample(sorted_entities, k)

    ml_set: Set[str] = set(ml_high_risk_entities)
    base_set: Set[str] = set(selected_baseline)
    overlap = sorted(list(ml_set.intersection(base_set)))

    overlap_ratio = len(overlap) / max(1, len(ml_set)) if ml_set else 0.0

    explanation = (
        f"Random Selection baseline prioritized {len(selected_baseline)} of {total} entities "
        f"(review rate {review_rate:.0%}, seed={seed}). "
        f"Compared to {len(ml_high_risk_entities)} ML/rule high-risk candidates, "
        f"the chance overlap is {len(overlap)} entities ({overlap_ratio:.0%})."
    )

    return BaselineComparisonMetrics(
        seed=seed,
        review_rate=review_rate,
        total_entities=total,
        baseline_selected_count=len(selected_baseline),
        ml_high_risk_count=len(ml_high_risk_entities),
        overlap_count=len(overlap),
        overlap_ratio=round(overlap_ratio, 4),
        overlap_entities=overlap,
        isolation_forest_selected=ml_high_risk_entities,
        random_baseline_selected=selected_baseline,
        explanation=explanation,
    )
