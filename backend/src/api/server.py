"""FastAPI server providing REST API for P-006 Risk Scoring Assessment."""

import io
import json
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from ..pipeline import export_assessment_to_files, run_assessment_pipeline
from ..schema import AssessmentOutput

app = FastAPI(
    title="P-006 Predictive Risk Scoring Assessment API",
    description="Local batch assessment API for insider-threat risk scoring (5-50 scale), Isolation Forest anomaly detection, Random Selection baseline, and explainable recommendations.",
    version="1.0.0",
)

# CORS Middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DEFAULT_DATA_FILE = DATA_DIR / "security_events.json"

# In-memory cached latest assessment
_latest_assessment: Optional[AssessmentOutput] = None


class RunAssessmentRequest(BaseModel):
    rule_weight: float = 0.60
    anomaly_weight: float = 0.40
    random_seed: int = 42
    baseline_review_rate: float = 0.25
    contamination: float = 0.15


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "P-006 Risk Scoring Engine"}


@app.get("/api/assessment/latest", response_model=AssessmentOutput)
def get_latest_assessment():
    global _latest_assessment
    if _latest_assessment is None:
        if not DEFAULT_DATA_FILE.exists():
            from ..data.generate_demo_data import generate_security_dataset
            generate_security_dataset(DATA_DIR)
        _latest_assessment = run_assessment_pipeline(file_path=DEFAULT_DATA_FILE)
    return _latest_assessment


@app.get("/api/assessment/entities/{entity_id}")
def get_entity_assessment(entity_id: str):
    global _latest_assessment
    if _latest_assessment is None:
        get_latest_assessment()

    for entity in _latest_assessment.entities:
        if entity.entity_id == entity_id:
            return entity

    raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found in current assessment run.")


@app.post("/api/assessment/run", response_model=AssessmentOutput)
def trigger_assessment(req: RunAssessmentRequest):
    global _latest_assessment
    if not DEFAULT_DATA_FILE.exists():
        from ..data.generate_demo_data import generate_security_dataset
        generate_security_dataset(DATA_DIR)

    _latest_assessment = run_assessment_pipeline(
        file_path=DEFAULT_DATA_FILE,
        rule_weight=req.rule_weight,
        anomaly_weight=req.anomaly_weight,
        random_seed=req.random_seed,
        baseline_review_rate=req.baseline_review_rate,
        contamination=req.contamination,
    )
    return _latest_assessment


@app.post("/api/assessment/upload", response_model=AssessmentOutput)
async def upload_and_assess(
    file: UploadFile = File(...),
    rule_weight: float = Query(0.60),
    anomaly_weight: float = Query(0.40),
    random_seed: int = Query(42),
    baseline_review_rate: float = Query(0.25),
):
    global _latest_assessment
    contents = await file.read()
    filename = file.filename or "uploaded.json"

    try:
        if filename.endswith(".json"):
            records = json.loads(contents.decode("utf-8"))
            if isinstance(records, dict) and "events" in records:
                records = records["events"]
        elif filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(contents), dtype=str)
            records = df.to_dict(orient="records")
        else:
            raise HTTPException(status_code=400, detail="Only .csv and .json files are supported")

        _latest_assessment = run_assessment_pipeline(
            records=records,
            rule_weight=rule_weight,
            anomaly_weight=anomaly_weight,
            random_seed=random_seed,
            baseline_review_rate=baseline_review_rate,
        )
        return _latest_assessment
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment failed on uploaded file: {str(e)}")


@app.get("/api/assessment/export/csv")
def export_csv():
    global _latest_assessment
    if _latest_assessment is None:
        get_latest_assessment()

    csv_rows = []
    for e in _latest_assessment.entities:
        contributors_str = "; ".join([f"{c.rule_name} (+{c.score_contribution})" for c in e.top_contributors])
        recs_str = "; ".join([r.title for r in e.recommendations])
        csv_rows.append({
            "run_id": _latest_assessment.run_id,
            "entity_id": e.entity_id,
            "entity_type": e.entity_type,
            "risk_score": e.risk_score,
            "risk_band": e.risk_band,
            "anomaly_score": e.anomaly_score,
            "rule_score": e.rule_score,
            "selected_by_random_baseline": e.selected_by_random_baseline,
            "top_contributors": contributors_str,
            "recommendations": recs_str,
        })

    df = pd.DataFrame(csv_rows)
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    stream.seek(0)

    return StreamingResponse(
        iter([stream.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=assessment_{_latest_assessment.run_id}.csv"},
    )


@app.get("/api/assessment/export/json")
def export_json():
    global _latest_assessment
    if _latest_assessment is None:
        get_latest_assessment()

    return Response(
        content=_latest_assessment.model_dump_json(indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=assessment_{_latest_assessment.run_id}.json"},
    )
