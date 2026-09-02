"""Rule and pattern detection engine for explainable risk signal extraction."""

from __future__ import annotations
from typing import Dict, List, Tuple
import pandas as pd
from .schema import RiskContributor


class RuleDefinition:
    def __init__(self, rule_id: str, name: str, default_severity: str, max_points: float, description_template: str):
        self.rule_id = rule_id
        self.name = name
        self.default_severity = default_severity
        self.max_points = max_points
        self.description_template = description_template


RULE_CATALOG = {
    "R_FAILED_LOGINS": RuleDefinition(
        rule_id="R_FAILED_LOGINS",
        name="Burst of Failed Authentication Attempts",
        default_severity="high",
        max_points=12.0,
        description_template="Observed {count} failed authentication attempts ({ratio:.0%} failure rate), indicating potential brute-force or credential stuffing.",
    ),
    "R_ODD_HOURS": RuleDefinition(
        rule_id="R_ODD_HOURS",
        name="Anomalous Off-Hours Activity",
        default_severity="medium",
        max_points=8.0,
        description_template="Entity generated {count} events during off-business hours ({ratio:.0%} of all entity activity).",
    ),
    "R_PRIV_ESCALATION": RuleDefinition(
        rule_id="R_PRIV_ESCALATION",
        name="Unauthorized Privilege / Role Modification",
        default_severity="critical",
        max_points=15.0,
        description_template="Detected {count} administrative privilege or permission escalation events.",
    ),
    "R_DATA_EXFIL": RuleDefinition(
        rule_id="R_DATA_EXFIL",
        name="Mass Data Transfer / Exfiltration Spike",
        default_severity="critical",
        max_points=15.0,
        description_template="High volume egress detected: {bytes_mb:.1f} MB total transferred (peak single transfer: {max_mb:.1f} MB).",
    ),
    "R_FW_DENIED": RuleDefinition(
        rule_id="R_FW_DENIED",
        name="Repeated Firewall Policy Denials",
        default_severity="high",
        max_points=10.0,
        description_template="Triggered {count} firewall denied/dropped connections, suggesting lateral movement or unauthorized port probing.",
    ),
    "R_DISTRIBUTED_IP": RuleDefinition(
        rule_id="R_DISTRIBUTED_IP",
        name="Multi-Source IP Access Spread",
        default_severity="medium",
        max_points=8.0,
        description_template="Activity originated from {count} distinct source IP addresses in the observed time window.",
    ),
    "R_CONFIG_CHANGE": RuleDefinition(
        rule_id="R_CONFIG_CHANGE",
        name="Critical System Configuration Changes",
        default_severity="high",
        max_points=10.0,
        description_template="Executed {count} configuration or security policy changes.",
    ),
}


def evaluate_entity_rules(row: pd.Series) -> Tuple[float, List[RiskContributor]]:
    """
    Evaluate all catalog rules against an entity's feature row.
    Returns:
        (total_rule_score, list_of_contributors)
    """
    contributors: List[RiskContributor] = []
    total_score = 0.0

    # 1. Failed Logins Rule
    failed_cnt = row.get("failed_login_count", 0.0)
    failed_ratio = row.get("failed_login_ratio", 0.0)
    if failed_cnt >= 3 or (failed_cnt >= 2 and failed_ratio >= 0.5):
        score = min(RULE_CATALOG["R_FAILED_LOGINS"].max_points, 4.0 + (failed_cnt * 1.5))
        severity = "critical" if failed_cnt >= 8 else ("high" if failed_cnt >= 4 else "medium")
        contributors.append(RiskContributor(
            rule_id="R_FAILED_LOGINS",
            rule_name=RULE_CATALOG["R_FAILED_LOGINS"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_FAILED_LOGINS"].description_template.format(
                count=int(failed_cnt), ratio=failed_ratio
            ),
            metric_value={"failed_login_count": int(failed_cnt), "failed_login_ratio": round(float(failed_ratio), 2)},
            threshold={"min_failures": 3, "min_ratio": 0.5},
        ))
        total_score += score

    # 2. Odd Hours Rule
    odd_cnt = row.get("odd_hour_count", 0.0)
    odd_ratio = row.get("odd_hour_ratio", 0.0)
    if odd_cnt >= 4 and odd_ratio >= 0.35:
        score = min(RULE_CATALOG["R_ODD_HOURS"].max_points, 3.0 + (odd_cnt * 0.8))
        severity = "high" if odd_ratio >= 0.7 else "medium"
        contributors.append(RiskContributor(
            rule_id="R_ODD_HOURS",
            rule_name=RULE_CATALOG["R_ODD_HOURS"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_ODD_HOURS"].description_template.format(
                count=int(odd_cnt), ratio=odd_ratio
            ),
            metric_value={"odd_hour_count": int(odd_cnt), "odd_hour_ratio": round(float(odd_ratio), 2)},
            threshold={"min_count": 4, "min_ratio": 0.35},
        ))
        total_score += score

    # 3. Privilege Escalation Rule
    priv_cnt = row.get("privilege_change_count", 0.0)
    if priv_cnt >= 1:
        score = min(RULE_CATALOG["R_PRIV_ESCALATION"].max_points, 8.0 + (priv_cnt * 3.5))
        severity = "critical" if priv_cnt >= 2 else "high"
        contributors.append(RiskContributor(
            rule_id="R_PRIV_ESCALATION",
            rule_name=RULE_CATALOG["R_PRIV_ESCALATION"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_PRIV_ESCALATION"].description_template.format(count=int(priv_cnt)),
            metric_value={"privilege_change_count": int(priv_cnt)},
            threshold={"min_count": 1},
        ))
        total_score += score

    # 4. Mass Data Exfiltration Rule
    total_bytes = row.get("total_bytes_transferred", 0.0)
    max_bytes = row.get("max_bytes_transferred", 0.0)
    mb_total = total_bytes / (1024 * 1024)
    mb_max = max_bytes / (1024 * 1024)
    if mb_total >= 25.0 or mb_max >= 15.0:
        score = min(RULE_CATALOG["R_DATA_EXFIL"].max_points, 6.0 + (mb_total / 10.0))
        severity = "critical" if mb_total >= 100.0 else "high"
        contributors.append(RiskContributor(
            rule_id="R_DATA_EXFIL",
            rule_name=RULE_CATALOG["R_DATA_EXFIL"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_DATA_EXFIL"].description_template.format(bytes_mb=mb_total, max_mb=mb_max),
            metric_value={"total_bytes_mb": round(mb_total, 2), "max_bytes_mb": round(mb_max, 2)},
            threshold={"min_total_mb": 25.0, "min_max_mb": 15.0},
        ))
        total_score += score

    # 5. Firewall Denied Spike Rule
    fw_cnt = row.get("firewall_denied_count", 0.0)
    if fw_cnt >= 3:
        score = min(RULE_CATALOG["R_FW_DENIED"].max_points, 4.0 + (fw_cnt * 1.5))
        severity = "critical" if fw_cnt >= 10 else ("high" if fw_cnt >= 5 else "medium")
        contributors.append(RiskContributor(
            rule_id="R_FW_DENIED",
            rule_name=RULE_CATALOG["R_FW_DENIED"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_FW_DENIED"].description_template.format(count=int(fw_cnt)),
            metric_value={"firewall_denied_count": int(fw_cnt)},
            threshold={"min_count": 3},
        ))
        total_score += score

    # 6. Distributed IP Access Rule
    ip_cnt = row.get("distinct_source_ips", 0.0)
    if ip_cnt >= 4:
        score = min(RULE_CATALOG["R_DISTRIBUTED_IP"].max_points, 3.0 + (ip_cnt * 1.2))
        severity = "high" if ip_cnt >= 7 else "medium"
        contributors.append(RiskContributor(
            rule_id="R_DISTRIBUTED_IP",
            rule_name=RULE_CATALOG["R_DISTRIBUTED_IP"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_DISTRIBUTED_IP"].description_template.format(count=int(ip_cnt)),
            metric_value={"distinct_source_ips": int(ip_cnt)},
            threshold={"min_count": 4},
        ))
        total_score += score

    # 7. Config Change Rule
    cfg_cnt = row.get("config_change_count", 0.0)
    if cfg_cnt >= 2:
        score = min(RULE_CATALOG["R_CONFIG_CHANGE"].max_points, 4.0 + (cfg_cnt * 2.0))
        severity = "high" if cfg_cnt >= 4 else "medium"
        contributors.append(RiskContributor(
            rule_id="R_CONFIG_CHANGE",
            rule_name=RULE_CATALOG["R_CONFIG_CHANGE"].name,
            severity=severity,
            score_contribution=round(score, 2),
            description=RULE_CATALOG["R_CONFIG_CHANGE"].description_template.format(count=int(cfg_cnt)),
            metric_value={"config_change_count": int(cfg_cnt)},
            threshold={"min_count": 2},
        ))
        total_score += score

    # Sort contributors by score contribution descending
    contributors.sort(key=lambda c: c.score_contribution, reverse=True)
    return round(total_score, 2), contributors


def compute_all_rule_scores(features_df: pd.DataFrame) -> Dict[str, Tuple[float, List[RiskContributor]]]:
    """Compute rule scores and contributors for all entities in features dataframe."""
    results = {}
    for _, row in features_df.iterrows():
        entity_id = row["entity_id"]
        score, contributors = evaluate_entity_rules(row)
        results[entity_id] = (score, contributors)
    return results
