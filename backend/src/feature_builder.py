"""Entity feature aggregation and behavioral vector builder."""

from __future__ import annotations
from typing import Dict, List, Tuple
import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
    "total_events",
    "login_count",
    "failed_login_count",
    "failed_login_ratio",
    "odd_hour_count",
    "odd_hour_ratio",
    "distinct_source_ips",
    "distinct_resources",
    "privilege_change_count",
    "config_change_count",
    "firewall_denied_count",
    "total_bytes_transferred",
    "max_bytes_transferred",
]


def build_entity_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
    """
    Aggregate raw security events into per-entity numerical feature vectors.
    Returns:
        (features_df, entity_type_map)
    """
    if df.empty or "entity_id" not in df.columns:
        return pd.DataFrame(columns=["entity_id"] + FEATURE_COLUMNS), {}

    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["datetime"]):
        df["datetime"] = pd.to_datetime(df["timestamp"])

    df["hour"] = df["datetime"].dt.hour
    df["is_odd_hour"] = (df["hour"] < 7) | (df["hour"] >= 19)

    # Normalize lowercase strings for robust matching
    df["event_type_norm"] = df["event_type"].str.lower().fillna("")
    df["outcome_norm"] = df["outcome"].str.lower().fillna("")

    entities = df["entity_id"].unique()
    feature_rows: List[Dict[str, float]] = []
    entity_type_map: Dict[str, str] = {}

    for entity_id in entities:
        sub = df[df["entity_id"] == entity_id]

        # Entity type resolution (mode or default)
        etype = sub["entity_type"].dropna().mode()
        entity_type_map[entity_id] = etype.iloc[0] if not etype.empty else "user"

        total_ev = len(sub)
        logins = sub[sub["event_type_norm"].str.contains("login|auth|sign_in")]
        login_cnt = len(logins)
        failed_logins = len(logins[logins["outcome_norm"].isin(["failure", "denied", "blocked", "failed"])])
        failed_login_ratio = failed_logins / max(1, login_cnt)

        odd_hours = sub["is_odd_hour"].sum()
        odd_hour_ratio = odd_hours / max(1, total_ev)

        distinct_ips = sub["source_ip"].dropna().nunique()
        distinct_res = sub["resource"].dropna().nunique()

        priv_changes = len(sub[sub["event_type_norm"].str.contains("privilege|role|grant|permission|admin")])
        cfg_changes = len(sub[sub["event_type_norm"].str.contains("config|policy|setting")])
        fw_denied = len(sub[(sub["event_type_norm"].str.contains("firewall|network")) & (sub["outcome_norm"].isin(["denied", "blocked", "drop"]))])

        total_bytes = sub["bytes_transferred"].fillna(0).sum()
        max_bytes = sub["bytes_transferred"].fillna(0).max() if not sub["bytes_transferred"].empty else 0.0

        feature_rows.append({
            "entity_id": entity_id,
            "total_events": float(total_ev),
            "login_count": float(login_cnt),
            "failed_login_count": float(failed_logins),
            "failed_login_ratio": float(failed_login_ratio),
            "odd_hour_count": float(odd_hours),
            "odd_hour_ratio": float(odd_hour_ratio),
            "distinct_source_ips": float(distinct_ips),
            "distinct_resources": float(distinct_res),
            "privilege_change_count": float(priv_changes),
            "config_change_count": float(cfg_changes),
            "firewall_denied_count": float(fw_denied),
            "total_bytes_transferred": float(total_bytes),
            "max_bytes_transferred": float(max_bytes),
        })

    feat_df = pd.DataFrame(feature_rows)
    # Ensure all columns present and fillna with 0.0
    for col in FEATURE_COLUMNS:
        if col not in feat_df.columns:
            feat_df[col] = 0.0
        feat_df[col] = feat_df[col].fillna(0.0)

    return feat_df, entity_type_map
