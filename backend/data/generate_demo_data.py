"""Synthetic security event dataset generator with normal and insider threat scenarios."""

from __future__ import annotations
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


def generate_security_dataset(
    output_dir: Path,
    num_normal_users: int = 16,
    include_quarantine_rows: bool = True,
) -> Tuple[Path, Path, Path]:
    """
    Generate synthetic security event datasets for multi-window dynamic testing:
    - Window 1 (Baseline): All entities (including alice, mscott, jdoe) behave routinely (normal health).
    - Window 2 (Active Threats): Threat scenarios emerge, triggering dynamic risk escalation.
    - Combined Dataset (Default): Full evaluation batch.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)

    base_time_w1 = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)
    base_time_w2 = datetime(2026, 9, 2, 8, 0, 0, tzinfo=timezone.utc)

    normal_users = [f"user_{name}" for name in [
        "bob", "carol", "dave", "emma", "frank", "grace", "heidi", "ivan",
        "judy", "kevin", "laura", "mike", "nina", "oscar", "peggy", "quinn"
    ][:num_normal_users]]

    # Include normal staff, benign-unusual on-call engineer, and 4 specific threat scenarios
    all_entities = normal_users + ["user_oncall_nate", "user_jdoe", "admin_mscott", "dev_alice", "service_backup"]

    # =========================================================================
    # Window 1: Baseline Routine Activity for ALL Entities (Low Risk Baseline)
    # =========================================================================
    w1_events: List[Dict[str, Any]] = []
    for ent in all_entities:
        num_ev = rng.randint(6, 12)
        user_ip = f"10.0.1.{rng.randint(20, 200)}"
        etype = "service_account" if ent == "service_backup" else "user"
        for i in range(num_ev):
            event_time = base_time_w1 + timedelta(hours=rng.randint(1, 8), minutes=rng.randint(0, 59))
            w1_events.append({
                "event_id": f"EVT-W1-NORM-{ent}-{i:03d}",
                "timestamp": event_time.isoformat(),
                "entity_id": ent,
                "entity_type": etype,
                "event_type": "login" if i == 0 else "file_access",
                "outcome": "success",
                "source_ip": user_ip,
                "resource": f"/shared/docs/quarterly_memo_{rng.randint(1, 5)}.pdf",
                "bytes_transferred": rng.randint(500, 20000),
                "severity": "info",
                "metadata": {"dept": "engineering" if "dev" in ent else "staff"},
            })

    # =========================================================================
    # Window 2: Threat Escalation Scenarios
    # =========================================================================
    w2_events: List[Dict[str, Any]] = []

    # 1. Normal routine continues for normal users
    for user in normal_users:
        num_ev = rng.randint(8, 14)
        user_ip = f"10.0.1.{rng.randint(20, 200)}"
        for i in range(num_ev):
            event_time = base_time_w2 + timedelta(hours=rng.randint(1, 9), minutes=rng.randint(0, 59))
            w2_events.append({
                "event_id": f"EVT-W2-NORM-{user}-{i:03d}",
                "timestamp": event_time.isoformat(),
                "entity_id": user,
                "entity_type": "user",
                "event_type": rng.choice(["login", "file_access", "file_access", "data_transfer"]),
                "outcome": "success",
                "source_ip": user_ip,
                "resource": f"/shared/docs/report_{rng.randint(1, 10)}.pdf",
                "bytes_transferred": rng.randint(500, 50000),
                "severity": "info",
                "metadata": {"dept": "marketing", "workstation": f"WS-{user}"},
            })

    # 1.1 Benign-Unusual User (On-Call Engineer: odd-hour logins and moderate data, but zero malicious triggers)
    for i in range(4):
        event_time = base_time_w2 + timedelta(hours=14, minutes=i * 25)  # 22:00 PM
        w2_events.append({
            "event_id": f"EVT-W2-ONCALL-nate-{i:03d}",
            "timestamp": event_time.isoformat(),
            "entity_id": "user_oncall_nate",
            "entity_type": "user",
            "event_type": "file_access" if i > 0 else "login",
            "outcome": "success",
            "source_ip": "10.0.1.99" if i % 2 == 0 else "10.0.1.100",
            "resource": "/infra/configs/router_backup.cfg",
            "bytes_transferred": 2 * 1024 * 1024,  # 2 MB
            "severity": "info",
            "metadata": {"ticket": "INC-8831-MAINTENANCE", "dept": "devops"},
        })

    # 2. Threat 1: user_jdoe (Brute-Force Auth Failures + Off-Hours Access)
    for i in range(6):
        w2_events.append({
            "event_id": f"EVT-W2-T1-FAIL-{i:03d}",
            "timestamp": (base_time_w2 + timedelta(hours=2, minutes=i * 3)).isoformat(),
            "entity_id": "user_jdoe",
            "entity_type": "user",
            "event_type": "login",
            "outcome": "failure",
            "source_ip": "198.51.100.44",
            "resource": "/auth/sso",
            "bytes_transferred": 0,
            "severity": "medium",
            "metadata": {"reason": "invalid_password"},
        })
    for i in range(5):
        w2_events.append({
            "event_id": f"EVT-W2-T1-ODD-{i:03d}",
            "timestamp": (base_time_w2 + timedelta(hours=18, minutes=30 + i * 15)).isoformat(),  # 02:30 AM
            "entity_id": "user_jdoe",
            "entity_type": "user",
            "event_type": "file_access",
            "outcome": "success",
            "source_ip": "198.51.100.44",
            "resource": "/secure/finance/q3_salary_data.xlsx",
            "bytes_transferred": 1200000,
            "severity": "high",
            "metadata": {"session": "nightly_ssh"},
        })

    # 3. Threat 2: admin_mscott (Privilege Escalation & Config Tampering)
    for i in range(3):
        w2_events.append({
            "event_id": f"EVT-W2-T2-PRIV-{i:03d}",
            "timestamp": (base_time_w2 + timedelta(hours=4, minutes=i * 10)).isoformat(),
            "entity_id": "admin_mscott",
            "entity_type": "user",
            "event_type": "privilege_change",
            "outcome": "success",
            "source_ip": "10.0.1.5",
            "resource": "/iam/roles/DomainAdmins",
            "bytes_transferred": 0,
            "severity": "critical",
            "metadata": {"target_grantee": "shadow_admin"},
        })
    for i in range(3):
        w2_events.append({
            "event_id": f"EVT-W2-T2-CFG-{i:03d}",
            "timestamp": (base_time_w2 + timedelta(hours=5, minutes=i * 8)).isoformat(),
            "entity_id": "admin_mscott",
            "entity_type": "user",
            "event_type": "config_change",
            "outcome": "success",
            "source_ip": "10.0.1.5",
            "resource": "/etc/auditd/auditd.conf",
            "bytes_transferred": 0,
            "severity": "high",
            "metadata": {"action": "disable_logging"},
        })

    # 4. Threat 3: dev_alice (Mass Data Exfiltration Burst)
    for i in range(4):
        w2_events.append({
            "event_id": f"EVT-W2-T3-EXFIL-{i:03d}",
            "timestamp": (base_time_w2 + timedelta(hours=6, minutes=i * 12)).isoformat(),
            "entity_id": "dev_alice",
            "entity_type": "user",
            "event_type": "data_transfer",
            "outcome": "success",
            "source_ip": "10.0.2.14",
            "resource": "/customer_db/dump_2026.tar.gz",
            "bytes_transferred": 35 * 1024 * 1024,  # 35 MB each
            "severity": "critical",
            "metadata": {"proto": "sftp", "dest": "203.0.113.88"},
        })

    # 5. Threat 4: service_backup (Firewall Denial Spike / Distributed Scanning)
    for i in range(6):
        w2_events.append({
            "event_id": f"EVT-W2-T4-FW-{i:03d}",
            "timestamp": (base_time_w2 + timedelta(hours=3, minutes=i * 5)).isoformat(),
            "entity_id": "service_backup",
            "entity_type": "service_account",
            "event_type": "firewall_event",
            "outcome": "denied",
            "source_ip": f"10.0.{i+10}.2",
            "resource": f"/port/{445 if i%2==0 else 3389}",
            "bytes_transferred": 0,
            "severity": "high",
            "metadata": {"action": "drop_packet", "rule": "FW-BLOCK-SMB-RDP"},
        })

    # 6. Malformed Rows in Window 2
    if include_quarantine_rows:
        w2_events.append({
            "event_id": "",
            "timestamp": (base_time_w2 + timedelta(hours=1)).isoformat(),
            "entity_id": "user_malformed_1",
            "event_type": "login",
            "outcome": "success",
        })
        w2_events.append({
            "event_id": "EVT-BAD-TIME-001",
            "timestamp": "INVALID_TIMESTAMP_STRING",
            "entity_id": "user_malformed_2",
            "event_type": "login",
            "outcome": "success",
        })
        w2_events.append({
            "event_id": "EVT-NO-ENTITY-001",
            "timestamp": (base_time_w2 + timedelta(hours=2)).isoformat(),
            "entity_id": "   ",
            "event_type": "file_access",
            "outcome": "success",
        })

    # Shuffle datasets
    rng.shuffle(w1_events)
    rng.shuffle(w2_events)

    # Save Window 1 (Baseline)
    w1_json_path = output_dir / "security_events_window1_baseline.json"
    with open(w1_json_path, "w", encoding="utf-8") as f:
        json.dump(w1_events, f, indent=2)

    # Save Window 2 / Default (Current Threats)
    w2_json_path = output_dir / "security_events_window2_threats.json"
    default_json_path = output_dir / "security_events.json"
    default_csv_path = output_dir / "security_events.csv"

    with open(w2_json_path, "w", encoding="utf-8") as f:
        json.dump(w2_events, f, indent=2)

    with open(default_json_path, "w", encoding="utf-8") as f:
        json.dump(w2_events, f, indent=2)

    # Serialize CSV
    csv_events = []
    for ev in w2_events:
        ev_copy = dict(ev)
        if isinstance(ev_copy.get("metadata"), dict):
            ev_copy["metadata"] = json.dumps(ev_copy["metadata"])
        csv_events.append(ev_copy)

    fieldnames = ["event_id", "timestamp", "entity_id", "entity_type", "event_type", "outcome", "source_ip", "resource", "bytes_transferred", "severity", "metadata"]
    with open(default_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_events:
            writer.writerow(row)

    print(f"Generated datasets:\n - Window 1 (Baseline): {len(w1_events)} events\n - Window 2 (Threats): {len(w2_events)} events")
    return w1_json_path, w2_json_path, default_json_path


if __name__ == "__main__":
    out_dir = Path(__file__).parent
    generate_security_dataset(out_dir)
