"""Ingestion and schema validation module with row quarantine."""

from __future__ import annotations
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union
import pandas as pd

from .schema import QuarantinedRow, RawSecurityEvent, ValidationSummary

REQUIRED_FIELDS = ["event_id", "timestamp", "entity_id", "event_type"]


def _validate_single_event(raw_dict: Dict[str, Any], index: int) -> Tuple[Optional[RawSecurityEvent], Optional[QuarantinedRow]]:
    """Validate a single raw event dictionary. Return (event, None) or (None, quarantined_row)."""
    missing = [f for f in REQUIRED_FIELDS if f not in raw_dict or raw_dict[f] is None or str(raw_dict[f]).strip() == ""]
    if missing:
        return None, QuarantinedRow(
            row_index=index,
            raw_record=raw_dict,
            reason=f"Missing required field(s): {', '.join(missing)}",
            missing_fields=missing,
        )

    # Validate timestamp parsing
    ts_str = str(raw_dict["timestamp"]).strip()
    try:
        # Handle ISO strings or common datetime formats
        datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception as e:
        return None, QuarantinedRow(
            row_index=index,
            raw_record=raw_dict,
            reason=f"Malformed ISO datetime format '{ts_str}': {str(e)}",
            missing_fields=[],
        )

    # Coerce numeric bytes
    bytes_val = raw_dict.get("bytes_transferred", 0.0)
    try:
        bytes_float = float(bytes_val) if bytes_val is not None and str(bytes_val).strip() != "" else 0.0
    except (ValueError, TypeError):
        bytes_float = 0.0

    # Handle metadata parsing if string or dict
    meta_raw = raw_dict.get("metadata")
    parsed_meta: Dict[str, Any] = {}
    if isinstance(meta_raw, dict):
        parsed_meta = meta_raw
    elif isinstance(meta_raw, str) and meta_raw.strip().startswith("{") and meta_raw.strip().endswith("}"):
        try:
            parsed_meta = json.loads(meta_raw)
        except Exception:
            parsed_meta = {}

    try:
        event = RawSecurityEvent(
            event_id=str(raw_dict["event_id"]).strip(),
            timestamp=ts_str,
            entity_id=str(raw_dict["entity_id"]).strip(),
            event_type=str(raw_dict["event_type"]).strip(),
            entity_type=str(raw_dict.get("entity_type", "user")).strip() or "user",
            outcome=str(raw_dict.get("outcome", "success")).strip() or "success",
            source_ip=str(raw_dict.get("source_ip", "")).strip() or None,
            resource=str(raw_dict.get("resource", "")).strip() or None,
            bytes_transferred=bytes_float,
            severity=str(raw_dict.get("severity", "info")).strip() or "info",
            metadata=parsed_meta,
        )
        return event, None
    except Exception as ex:
        return None, QuarantinedRow(
            row_index=index,
            raw_record=raw_dict,
            reason=f"Pydantic validation error: {str(ex)}",
            missing_fields=[],
        )


def ingest_records(records: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, ValidationSummary]:
    """Ingest a list of raw event dicts, separating valid rows from quarantined rows."""
    valid_events: List[RawSecurityEvent] = []
    quarantined: List[QuarantinedRow] = []

    for idx, record in enumerate(records):
        valid, bad = _validate_single_event(record, idx)
        if valid:
            valid_events.append(valid)
        else:
            if bad:
                quarantined.append(bad)

    summary = ValidationSummary(
        total_rows_read=len(records),
        valid_rows_count=len(valid_events),
        quarantined_rows_count=len(quarantined),
        quarantined_details=quarantined,
        has_quarantined_data=len(quarantined) > 0,
        validation_status="VALID" if len(quarantined) == 0 else ("PARTIAL" if len(valid_events) > 0 else "FAILED"),
    )

    if not valid_events:
        return pd.DataFrame(), summary

    df = pd.DataFrame([e.model_dump() for e in valid_events])
    df["datetime"] = pd.to_datetime(df["timestamp"])
    return df, summary


def load_and_ingest_file(file_path: Union[str, Path]) -> Tuple[pd.DataFrame, ValidationSummary]:
    """Load and ingest CSV or JSON file from local disk."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    suffix = path.suffix.lower()
    records: List[Dict[str, Any]] = []

    if suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict) and "events" in data:
                records = data["events"]
            else:
                raise ValueError("JSON file must be a list of events or an object with an 'events' list")
    elif suffix in [".csv", ".tsv"]:
        try:
            raw_df = pd.read_csv(path, dtype=str)
            records = raw_df.to_dict(orient="records")
        except pd.errors.EmptyDataError:
            records = []
    else:
        raise ValueError(f"Unsupported file format: {suffix}. Expected .csv, .tsv, or .json")

    return ingest_records(records)
