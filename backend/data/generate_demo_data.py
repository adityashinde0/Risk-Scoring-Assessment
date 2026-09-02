"""Synthetic security event dataset generator with normal and insider threat scenarios."""

from __future__ import annotations
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


def generate_security_dataset(output_dir: Path, num_normal_users: int = 16, include_quarantine_rows: bool = True) -> Path:
    """Generate synthetic security event dataset with realistic normal and threat patterns."""
    output_dir.mkdir(parents=True, exist_ok=True)
    events: List[Dict[str, Any]] = []

    base_time = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)
    rng = random.Random(42)

    # 1. Generate Normal Users (Routine behavior)
    normal_users = [f"user_{name}" for name in [
        "bob", "carol", "dave", "emma", "frank", "grace", "heidi", "ivan",
        "judy", "kevin", "laura", "mike", "nina", "oscar", "peggy", "quinn"
    ][:num_normal_users]]

    for user in normal_users:
        # 8-15 normal events during 09:00 - 17:00
        num_ev = rng.randint(8, 15)
        user_ip = f"10.0.1.{rng.randint(20, 200)}"
        for i in range(num_ev):
            event_time = base_time + timedelta(hours=rng.randint(1, 9), minutes=rng.randint(0, 59))
            ev_type = rng.choice(["login", "file_access", "file_access", "data_transfer"])
            events.append({
                "event_id": f"EVT-NORM-{user}-{i:03d}",
                "timestamp": event_time.isoformat(),
                "entity_id": user,
                "entity_type": "user",
                "event_type": ev_type,
                "outcome": "success",
                "source_ip": user_ip,
                "resource": f"/shared/docs/report_{rng.randint(1, 10)}.pdf",
                "bytes_transferred": rng.randint(500, 50000),
                "severity": "info",
                "metadata": {"dept": "marketing", "workstation": f"WS-{user}"},
            })

    # 2. Threat Scenario 1: Compromised Account - Brute Force + Odd-Hours Access (user_jdoe)
    for i in range(6):
        # Failed login burst
        events.append({
            "event_id": f"EVT-THREAT1-FAIL-{i:03d}",
            "timestamp": (base_time + timedelta(hours=2, minutes=i * 3)).isoformat(),
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
    # Subsequent odd-hour successful access
    for i in range(5):
        events.append({
            "event_id": f"EVT-THREAT1-ODD-{i:03d}",
            "timestamp": (base_time + timedelta(hours=18, minutes=30 + i * 15)).isoformat(),  # 02:30 AM
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

    # 3. Threat Scenario 2: Rogue Administrator Privilege Escalation (admin_mscott)
    for i in range(3):
        events.append({
            "event_id": f"EVT-THREAT2-PRIV-{i:03d}",
            "timestamp": (base_time + timedelta(hours=4, minutes=i * 10)).isoformat(),
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
        events.append({
            "event_id": f"EVT-THREAT2-CFG-{i:03d}",
            "timestamp": (base_time + timedelta(hours=5, minutes=i * 8)).isoformat(),
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

    # 4. Threat Scenario 3: Massive Data Exfiltration Burst (dev_alice)
    for i in range(4):
        events.append({
            "event_id": f"EVT-THREAT3-EXFIL-{i:03d}",
            "timestamp": (base_time + timedelta(hours=6, minutes=i * 12)).isoformat(),
            "entity_id": "dev_alice",
            "entity_type": "user",
            "event_type": "data_transfer",
            "outcome": "success",
            "source_ip": "10.0.2.14",
            "resource": "/customer_db/dump_2026.tar.gz",
            "bytes_transferred": 35 * 1024 * 1024,  # 35 MB each = 140 MB total
            "severity": "critical",
            "metadata": {"proto": "sftp", "dest": "203.0.113.88"},
        })

    # 5. Threat Scenario 4: Firewall Probe / Distributed Scanning (service_backup)
    for i in range(6):
        events.append({
            "event_id": f"EVT-THREAT4-FW-{i:03d}",
            "timestamp": (base_time + timedelta(hours=3, minutes=i * 5)).isoformat(),
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

    # 6. Add malformed rows to test schema validation and row quarantine
    if include_quarantine_rows:
        events.append({
            "event_id": "",  # Missing event_id
            "timestamp": (base_time + timedelta(hours=1)).isoformat(),
            "entity_id": "user_malformed_1",
            "event_type": "login",
            "outcome": "success",
        })
        events.append({
            "event_id": "EVT-BAD-TIME-001",
            "timestamp": "INVALID_TIMESTAMP_STRING",  # Invalid timestamp
            "entity_id": "user_malformed_2",
            "event_type": "login",
            "outcome": "success",
        })
        events.append({
            "event_id": "EVT-NO-ENTITY-001",
            "timestamp": (base_time + timedelta(hours=2)).isoformat(),
            "entity_id": "   ",  # Blank entity_id
            "event_type": "file_access",
            "outcome": "success",
        })

    # Shuffle for realistic chronological interleave
    rng.shuffle(events)

    # Save to JSON and CSV
    json_path = output_dir / "security_events.json"
    csv_path = output_dir / "security_events.csv"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    # For CSV, serialize metadata as json string
    csv_events = []
    for ev in events:
        ev_copy = dict(ev)
        if isinstance(ev_copy.get("metadata"), dict):
            ev_copy["metadata"] = json.dumps(ev_copy["metadata"])
        csv_events.append(ev_copy)

    fieldnames = ["event_id", "timestamp", "entity_id", "entity_type", "event_type", "outcome", "source_ip", "resource", "bytes_transferred", "severity", "metadata"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_events:
            writer.writerow(row)

    print(f"Generated {len(events)} events ({json_path}, {csv_path})")
    return json_path


if __name__ == "__main__":
    out_dir = Path(__file__).parent
    generate_security_dataset(out_dir)
