"""Recommendation engine mapping risk contributors to safe, actionable analyst guidance."""

from __future__ import annotations
import uuid
from typing import List
from .schema import Recommendation, RiskContributor


RECOMMENDATION_MAPPINGS = {
    "R_FAILED_LOGINS": {
        "title": "Enforce MFA Challenge & Review Auth Logs",
        "action_type": "session_revocation",
        "description": "Terminate active sessions, trigger immediate step-up Multi-Factor Authentication (MFA), and audit failed authentication source IPs for credential stuffing.",
    },
    "R_PRIV_ESCALATION": {
        "title": "Audit IAM Privilege Escalation & Verify Change Ticket",
        "action_type": "privilege_audit",
        "description": "Perform an urgent access review on recently granted administrative permissions. Validate against approved Jira/ServiceNow change request tickets.",
    },
    "R_DATA_EXFIL": {
        "title": "Inspect Egress DLP & Quarantine Outbound Transfers",
        "action_type": "host_investigation",
        "description": "Analyze network DLP and flow logs for data exfiltration destinations. Validate if egress volume matches authorized business workflows or backup jobs.",
    },
    "R_FW_DENIED": {
        "title": "Tune Firewall Ingress/Egress Rules & Block Scanning IPs",
        "action_type": "firewall_tuning",
        "description": "Review firewall denial patterns. Block malicious source IPs at border routers and tune rate-limiting thresholds on targeted ports.",
    },
    "R_ODD_HOURS": {
        "title": "Validate Off-Hours Activity & Schedule Window",
        "action_type": "configuration_review",
        "description": "Confirm whether off-hours access was authorized under an emergency maintenance window or indicates compromised off-shift credentials.",
    },
    "R_DISTRIBUTED_IP": {
        "title": "Enforce Geolocation & IP Whitelist Constraints",
        "action_type": "firewall_tuning",
        "description": "Inspect multi-IP origin logs for concurrent impossible travel. Apply conditional access policies to restrict entity access to approved corporate subnets.",
    },
    "R_CONFIG_CHANGE": {
        "title": "Rollback / Verify Unauthorized System Configuration",
        "action_type": "configuration_review",
        "description": "Diff recent configuration changes against hardened CIS security benchmarks. Verify approval in version-controlled infrastructure repositories.",
    },
}


def generate_recommendations(
    entity_id: str,
    risk_score: float,
    risk_band: str,
    contributors: List[RiskContributor],
) -> List[Recommendation]:
    """
    Generate prioritized, analyst-safe mitigation recommendations from active risk contributors.
    Ensures high and critical entities always receive at least one recommendation.
    """
    recommendations: List[Recommendation] = []
    seen_rules = set()

    for c in contributors:
        if c.rule_id in RECOMMENDATION_MAPPINGS and c.rule_id not in seen_rules:
            seen_rules.add(c.rule_id)
            template = RECOMMENDATION_MAPPINGS[c.rule_id]
            recommendations.append(Recommendation(
                recommendation_id=f"REC-{c.rule_id}-{entity_id[:8]}",
                title=template["title"],
                action_type=template["action_type"],
                description=template["description"],
                priority=c.severity,
                target_entity=entity_id,
            ))

    # Engineering Invariant: High/Critical risk entities must have at least one recommendation
    if not recommendations and (risk_band in ["high", "critical"] or risk_score >= 30.0):
        recommendations.append(Recommendation(
            recommendation_id=f"REC-GENERIC-{entity_id[:8]}",
            title="Conduct Comprehensive Entity Risk Review",
            action_type="host_investigation",
            description="Statistical anomaly detected by Isolation Forest without specific rule trigger. Review recent session logs, endpoint processes, and access history.",
            priority=risk_band,
            target_entity=entity_id,
        ))

    return recommendations
