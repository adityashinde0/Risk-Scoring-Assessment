"""Comprehensive automated invariant, evaluation, and robustness tests for P-006 Risk Scoring Assessment."""

import sys
import tempfile
from pathlib import Path
import pytest
import pandas as pd
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from src.evaluation import evaluate_assessment_methods, DEMO_GROUND_TRUTH_THREATS
from src.ingestion import ingest_records, load_and_ingest_file
from src.pipeline import run_assessment_pipeline
from src.risk_normalizer import calculate_normalized_risk_score
from src.baseline import generate_random_baseline
from src.schema import RawSecurityEvent, QuarantinedRow, AssessmentOutput
from src.api.server import app


@pytest.fixture
def sample_events_path():
    return backend_dir / "data" / "security_events.json"


@pytest.fixture
def window1_path():
    return backend_dir / "data" / "security_events_window1_baseline.json"


@pytest.fixture
def window2_path():
    return backend_dir / "data" / "security_events_window2_threats.json"


@pytest.fixture
def sample_csv_path():
    return backend_dir / "data" / "security_events.csv"


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


def test_csv_ingestion_and_metadata_parsing(sample_csv_path):
    """Test CSV ingestion preserves JSON string metadata into dictionary."""
    valid_df, val_summary = load_and_ingest_file(sample_csv_path)
    assert not valid_df.empty
    assert val_summary.valid_rows_count > 0
    for meta in valid_df["metadata"]:
        assert isinstance(meta, dict)


def test_empty_csv_file_graceful_handling():
    """Test loading an empty CSV file does not crash."""
    with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
        f.write("")
        temp_path = f.name

    try:
        valid_df, val_summary = load_and_ingest_file(temp_path)
        assert valid_df.empty
        assert val_summary.valid_rows_count == 0
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_evaluation_benchmark_metrics(sample_events_path):
    """Verify evaluation benchmark report correctly computes precision, recall, F1 across all 4 methods."""
    result = run_assessment_pipeline(file_path=sample_events_path, random_seed=42)
    assert result.evaluation_benchmark is not None

    eval_report = evaluate_assessment_methods(result)
    assert len(eval_report.methods) == 4
    assert eval_report.is_synthetic_benchmark is True
    assert len(eval_report.disclaimer) > 0

    combined_m = next(m for m in eval_report.methods if "Combined" in m.method_name)
    random_m = next(m for m in eval_report.methods if "Random" in m.method_name)

    assert 0.0 <= combined_m.precision <= 1.0
    assert 0.0 <= combined_m.recall <= 1.0
    assert 0.0 <= combined_m.f1_score <= 1.0
    # Combined model should capture threat scenarios effectively
    assert combined_m.recall >= 0.75
    assert combined_m.f1_score > random_m.f1_score


def test_dynamic_window_score_shift(window1_path, window2_path):
    """Verify dynamic score adaptation: Window 1 (routine baseline) vs Window 2 (incident escalation)."""
    # Assess Window 1
    w1_res = run_assessment_pipeline(file_path=window1_path, window_id="window_1_baseline")
    assert w1_res.risk_band_counts["critical"] == 0

    # Assess Window 2 with Window 1 as historical baseline
    w2_res = run_assessment_pipeline(
        file_path=window2_path,
        window_id="window_2_threats",
        baseline_history_file=window1_path,
    )

    # Check that threat entities escalated significantly
    alice = next(e for e in w2_res.entities if e.entity_id == "dev_alice")
    jdoe = next(e for e in w2_res.entities if e.entity_id == "user_jdoe")
    mscott = next(e for e in w2_res.entities if e.entity_id == "admin_mscott")

    assert alice.risk_score >= 30.0
    assert alice.score_delta is not None and alice.score_delta >= 10.0
    assert alice.trend_status == "ESCALATED"

    assert jdoe.risk_score >= 30.0
    assert jdoe.score_delta is not None and jdoe.score_delta >= 10.0

    assert mscott.risk_score >= 30.0
    assert mscott.score_delta is not None and mscott.score_delta >= 10.0


def test_score_sensitivity_to_threat_injection():
    """Verify that injecting malicious authentication and exfiltration events increases an entity's risk score."""
    base_events = [
        {"event_id": f"E-{i}", "timestamp": f"2026-09-01T10:0{i}:00Z", "entity_id": "test_subject", "event_type": "login", "outcome": "success"}
        for i in range(5)
    ]
    res_clean = run_assessment_pipeline(records=base_events)
    clean_score = res_clean.entities[0].risk_score

    # Add 8 failed logins and 50MB exfiltration
    malicious_events = list(base_events) + [
        {"event_id": f"MAL-F-{i}", "timestamp": f"2026-09-01T11:0{i}:00Z", "entity_id": "test_subject", "event_type": "login", "outcome": "failure"}
        for i in range(8)
    ] + [
        {"event_id": "MAL-EX-1", "timestamp": "2026-09-01T12:00:00Z", "entity_id": "test_subject", "event_type": "data_transfer", "outcome": "success", "bytes_transferred": 50 * 1024 * 1024}
    ]

    res_dirty = run_assessment_pipeline(records=malicious_events)
    dirty_score = res_dirty.entities[0].risk_score

    assert dirty_score > clean_score + 15.0
    assert dirty_score <= 50.0
    assert len(res_dirty.entities[0].top_contributors) >= 2


def test_recommendation_linkage_to_contributors(sample_events_path):
    """Verify recommendations are explicitly linked to detected risk contributor rules."""
    result = run_assessment_pipeline(file_path=sample_events_path)
    for entity in result.entities:
        active_rule_ids = set([c.rule_id for c in entity.top_contributors])
        if "R_FAILED_LOGINS" in active_rule_ids:
            assert any("MFA" in r.title or "Auth" in r.title for r in entity.recommendations)
        if "R_PRIV_ESCALATION" in active_rule_ids:
            assert any("Privilege" in r.title or "IAM" in r.title for r in entity.recommendations)
        if "R_DATA_EXFIL" in active_rule_ids:
            assert any("DLP" in r.title or "Egress" in r.title for r in entity.recommendations)
        if "R_FW_DENIED" in active_rule_ids:
            assert any("Firewall" in r.title or "ACL" in r.title for r in entity.recommendations)


def test_api_endpoints_integration():
    """Test FastAPI integration: latest, evaluation, entity detail, and run endpoints."""
    client = TestClient(app)

    # 1. Latest endpoint
    latest_res = client.get("/api/assessment/latest")
    assert latest_res.status_code == 200
    latest_data = latest_res.json()
    assert len(latest_data["entities"]) > 0

    # 2. Evaluation endpoint
    eval_res = client.get("/api/assessment/evaluation")
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert len(eval_data["methods"]) == 4

    # 3. Entity endpoint
    first_ent = latest_data["entities"][0]["entity_id"]
    ent_res = client.get(f"/api/assessment/entities/{first_ent}")
    assert ent_res.status_code == 200
    assert ent_res.json()["entity_id"] == first_ent

    # 4. Window run endpoint
    w1_res = client.post("/api/assessment/run", json={"window": "window_1_baseline", "random_seed": 42})
    assert w1_res.status_code == 200
    assert w1_res.json()["window_id"] == "window_1_baseline"
