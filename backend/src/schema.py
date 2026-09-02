"""Schema contracts and validation models for P-006 Predictive Risk Scoring Assessment."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class RawSecurityEvent(BaseModel):
    """Raw security event representation as ingested."""
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: str = Field(..., description="ISO 8601 datetime format")
    entity_id: str = Field(..., description="User/host/service/device principal identifier")
    event_type: str = Field(..., description="Type of security event (login, file_access, etc.)")
    entity_type: Optional[str] = Field(default="user", description="Category: user, host, service_account, device, ip")
    outcome: Optional[str] = Field(default="success", description="Outcome: success, failure, denied, allowed")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    resource: Optional[str] = Field(default=None, description="Resource accessed or target entity")
    bytes_transferred: Optional[float] = Field(default=0.0, description="Volume of data transferred")
    severity: Optional[str] = Field(default="info", description="Source severity rating")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary metadata dictionary")


class QuarantinedRow(BaseModel):
    """Record of an invalid input row quarantined during schema validation."""
    row_index: int
    raw_record: Dict[str, Any]
    reason: str
    missing_fields: List[str] = Field(default_factory=list)


class ValidationSummary(BaseModel):
    """Ingestion and schema validation summary."""
    total_rows_read: int
    valid_rows_count: int
    quarantined_rows_count: int
    quarantined_details: List[QuarantinedRow] = Field(default_factory=list)
    has_quarantined_data: bool = False
    validation_status: str = "VALID"  # VALID, PARTIAL, FAILED


class RiskContributor(BaseModel):
    """Individual rule or anomaly indicator contributing to the entity risk score."""
    rule_id: str
    rule_name: str
    severity: str  # low, medium, high, critical
    score_contribution: float
    description: str
    metric_value: Optional[Any] = None
    threshold: Optional[Any] = None


class Recommendation(BaseModel):
    """Actionable mitigation recommendation for security analysts and admins."""
    recommendation_id: str
    title: str
    action_type: str  # configuration_review, firewall_tuning, session_revocation, privilege_audit, host_investigation
    description: str
    priority: str  # low, medium, high, critical
    target_entity: str


class EntityAssessmentResult(BaseModel):
    """Assessment record for a single scored entity."""
    entity_id: str
    entity_type: str = "user"
    risk_score: float = Field(..., ge=5.0, le=50.0, description="Dynamic risk score in range 5.0 to 50.0")
    risk_band: str = Field(..., description="low, medium, high, critical")
    previous_risk_score: Optional[float] = Field(default=None, description="Previous window risk score if historical window exists")
    score_delta: Optional[float] = Field(default=None, description="Change in score compared to previous window (+/-)")
    trend_status: Optional[str] = Field(default="STABLE", description="ESCALATED, STABLE, REDUCED")
    anomaly_score: Optional[float] = Field(default=None, description="Normalized Isolation Forest anomaly signal (0.0 to 1.0)")
    raw_anomaly_score: Optional[float] = Field(default=None, description="Raw model decision function score")
    rule_score: float = Field(..., description="Aggregated explainable rule severity score")
    top_contributors: List[RiskContributor] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    selected_by_random_baseline: bool = False
    validation_warnings: List[str] = Field(default_factory=list)
    feature_summary: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("risk_score")
    @classmethod
    def validate_score_range(cls, v: float) -> float:
        if v < 5.0 or v > 50.0:
            raise ValueError(f"Engineering Invariant Violated: risk_score {v} is outside strict bounds [5.0, 50.0]")
        return round(v, 2)


class BaselineComparisonMetrics(BaseModel):
    """Comparative evaluation metrics between ML scoring and Random Selection baseline."""
    seed: int
    review_rate: float
    total_entities: int
    baseline_selected_count: int
    ml_high_risk_count: int
    overlap_count: int
    overlap_ratio: float
    overlap_entities: List[str] = Field(default_factory=list)
    isolation_forest_selected: List[str] = Field(default_factory=list)
    random_baseline_selected: List[str] = Field(default_factory=list)
    explanation: str


class AssessmentOutput(BaseModel):
    """Complete assessment payload contract consumed by API and React dashboard."""
    run_id: str
    window_id: str = "current_window"
    generated_at: str
    total_entities_evaluated: int
    risk_band_counts: Dict[str, int]
    entities: List[EntityAssessmentResult]
    baseline_comparison: BaselineComparisonMetrics
    validation_summary: ValidationSummary
    scoring_config: Dict[str, Any]
    model_status: str  # FIT_SUCCESS, FALLBACK_RULE_ONLY
    evaluation_benchmark: Optional[Dict[str, Any]] = None
