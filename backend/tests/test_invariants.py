"""Comprehensive automated invariant and robustness tests for P-006 Risk Scoring Assessment."""

import sys
from pathlib import Path
import pytest
import pandas as pd

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from src.ingestion import ingest_records, load_and_ingest_file
from src.pipeline import run_assessment_pipeline
from src.risk_normalizer import calculate_normalized_risk_score
from src.baseline import generate_random_baseline
from src.schema import RawSecurityEvent, QuarantinedRow, AssessmentOutput


@pytest.fixture
def sample_events_path():
    return backend_dir / "data" / "security_events.json"


def test_invariant_1_score_bounds_and_validity(sample_events_path):
    """Invariant: 100% of final risk scores must be strictly between 5.0 and 50.0."""
    result = run_assessment_pipeline(file_path=sample_events_path, random_seed=42)
    assert result.total_entities_evaluated > 0

    for entity in result.entities:
        assert 5.0 <= entity.risk_score <= 50.0, f"Score {entity.risk_score} for {entity.entity_id} violated [5.0, 50.0]"
        assert entity.risk_band in ["low", "medium", "high", "critical"]
        if entity.anomaly_score is not None:
            assert 0.0 <= entity.anomaly_score <= 1.0


def test_invariant_2_entity_id_integrity(sample_events_path):
    """Invariant: Every scored entity must possess a non-empty entity_id."""
    result = run_assessment_pipeline(file_path=sample_events_path)
    for entity in result.entities:
        assert entity.entity_id is not None
        assert len(entity.entity_id.strip()) > 0


def test_invariant_3_high_risk_explanation_coverage(sample_events_path):
    """Invariant: Every high-risk or critical entity must include at least one contributor and one recommendation."""
    result = run_assessment_pipeline(file_path=sample_events_path)
    for entity in result.entities:
        if entity.risk_band in ["high", "critical"] or entity.risk_score >= 30.0:
            assert len(entity.top_contributors) > 0 or entity.anomaly_score is not None, (
                f"High-risk entity {entity.entity_id} missing contributor explanation"
            )
            assert len(entity.recommendations) > 0, (
                f"High-risk entity {entity.entity_id} missing actionable recommendation"
            )
            for rec in entity.recommendations:
                assert rec.target_entity == entity.entity_id
                assert len(rec.title) > 0
                assert len(rec.description) > 0


def test_invariant_4_baseline_population_alignment(sample_events_path):
    """Invariant: Random Selection baseline must draw strictly from the same scored entity population."""
    result = run_assessment_pipeline(file_path=sample_events_path, baseline_review_rate=0.3, random_seed=42)
    all_entity_ids = set([e.entity_id for e in result.entities])
    baseline_selected = set(result.baseline_comparison.random_baseline_selected)

    assert baseline_selected.issubset(all_entity_ids), "Random baseline selected entity outside population!"
    assert result.baseline_comparison.total_entities == len(all_entity_ids)
    assert 0.0 <= result.baseline_comparison.overlap_ratio <= 1.0


def test_invariant_5_row_quarantine_resilience():
    """Invariant: Invalid rows must be quarantined without failing the valid row assessment."""
    mixed_records = [
        # Valid row 1
        {
            "event_id": "EV-001",
            "timestamp": "2026-09-01T10:00:00Z",
            "entity_id": "user_test_valid",
            "event_type": "login",
            "outcome": "success",
        },
        # Invalid row: missing timestamp
        {
            "event_id": "EV-002",
            "entity_id": "user_test_bad_1",
            "event_type": "login",
        },
        # Invalid row: unparseable timestamp
        {
            "event_id": "EV-003",
            "timestamp": "NOT_A_DATE",
            "entity_id": "user_test_bad_2",
            "event_type": "login",
        },
        # Invalid row: missing entity_id
        {
            "event_id": "EV-004",
            "timestamp": "2026-09-01T10:05:00Z",
            "event_type": "login",
        },
        # Valid row 2
        {
            "event_id": "EV-005",
            "timestamp": "2026-09-01T10:10:00Z",
            "entity_id": "user_test_valid",
            "event_type": "file_access",
            "outcome": "success",
        },
    ]

    valid_df, val_summary = ingest_records(mixed_records)
    assert len(valid_df) == 2
    assert val_summary.quarantined_rows_count == 3
    assert val_summary.valid_rows_count == 2
    assert val_summary.has_quarantined_data is True
    assert val_summary.validation_status == "PARTIAL"

    # Assessment must run smoothly on the valid subset
    result = run_assessment_pipeline(records=mixed_records)
    assert result.total_entities_evaluated == 1
    assert result.entities[0].entity_id == "user_test_valid"
    assert result.validation_summary.quarantined_rows_count == 3


def test_invariant_6_reproducibility_with_seed(sample_events_path):
    """Invariant: Running with identical data and seed yields bitwise identical scores and baseline candidates."""
    res1 = run_assessment_pipeline(file_path=sample_events_path, random_seed=999)
    res2 = run_assessment_pipeline(file_path=sample_events_path, random_seed=999)

    assert res1.baseline_comparison.random_baseline_selected == res2.baseline_comparison.random_baseline_selected

    scores1 = {e.entity_id: (e.risk_score, e.anomaly_score, e.selected_by_random_baseline) for e in res1.entities}
    scores2 = {e.entity_id: (e.risk_score, e.anomaly_score, e.selected_by_random_baseline) for e in res2.entities}

    assert scores1 == scores2


def test_extreme_score_clamping():
    """Invariant: Risk normalizer strictly bounds any artificial extreme score within [5.0, 50.0]."""
    # Test zero inputs
    low_score, low_band = calculate_normalized_risk_score(rule_score=0.0, anomaly_score=0.0)
    assert low_score == 5.0
    assert low_band == "low"

    # Test extreme high inputs
    high_score, high_band = calculate_normalized_risk_score(rule_score=1000.0, anomaly_score=1.0)
    assert high_score == 50.0
    assert high_band == "critical"

    # Test negative anomaly
    neg_score, _ = calculate_normalized_risk_score(rule_score=-50.0, anomaly_score=-1.0)
    assert neg_score == 5.0


def test_empty_dataset_graceful_handling():
    """Test pipeline gracefully produces empty assessment on empty input."""
    result = run_assessment_pipeline(records=[])
    assert result.total_entities_evaluated == 0
    assert len(result.entities) == 0
    assert result.model_status == "FALLBACK_RULE_ONLY"
