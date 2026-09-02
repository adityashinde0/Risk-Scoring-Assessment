# P-006: Predictive Risk Scoring Assessment

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/React-18.x-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/scikit--learn-Isolation_Forest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Vite-6.x-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Pytest-8%2F8%20Passed-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" alt="Pytest" />
</p>

<p align="center">
  <strong>Dynamic insider-threat scoring (5.0–50.0 scale) combining unsupervised Isolation Forest anomaly detection, explainable rule extraction, deterministic Random Selection control, and a real-time SOC analyst dashboard.</strong>
</p>

---

## 📑 Table of Contents
- [1. Architecture & System Flow](#1-architecture--system-flow)
- [2. Threat Triage & Scoring Model](#2-threat-triage--scoring-model)
- [3. Key Features & Engineering Invariants](#3-key-features--engineering-invariants)
- [4. Rule Catalog & Mitigation Playbook](#4-rule-catalog--mitigation-playbook)
- [5. Project Directory Structure](#5-project-directory-structure)
- [6. Quickstart Guide](#6-quickstart-guide)
- [7. REST API Reference](#7-rest-api-reference)
- [8. Automated Test Suite](#8-automated-test-suite)

---

## 1. Architecture & System Flow

The platform executes a local batch-scoring workflow that extracts behavioral indicators from event logs, scores statistical isolation via machine learning, evaluates domain threat rules, and normalizes scores into strict bounds for human review.

```mermaid
flowchart TD
    subgraph INGESTION ["1. Data Ingestion & Integrity Layer"]
        A[Security Event Logs\nCSV / JSON] --> B[Schema Validator\nRequired Field Check]
        B -->|Valid Records| C[Valid Events Buffer]
        B -->|Corrupted / Missing Fields| Q[Row Quarantine Report\nNon-blocking Error Log]
    end

    subgraph ENGINE ["2. Behavioral Signal Extraction & ML Scoring"]
        C --> D[Entity Feature Aggregator\nTime Window Aggregation]
        D --> E[Rule & Pattern Engine\nDomain Threat Catalog]
        D --> F[Isolation Forest Scorer\nUnsupervised Anomaly Model]
        D --> G[Random Selection Baseline\nDeterministic Seed Control]
    end

    subgraph NORMALIZATION ["3. Risk Synthesis & Normalization"]
        E -->|Rule Points| H[Risk Normalizer\nBounded 5.0 - 50.0 Scale]
        F -->|Anomaly Percentile| H
        H --> I[Risk Band Assignment\nLow / Medium / High / Critical]
        I --> J[Recommendation Engine\nActionable Mitigation Mapping]
    end

    subgraph PRESENTATION ["4. Delivery & SOC Analyst Interface"]
        G --> K[Baseline Overlap Metrics]
        J --> L[Assessment Output Payload\nJSON & CSV Artifacts]
        K --> L
        Q --> L
        L --> M[FastAPI REST Service\nlocalhost:8000]
        M --> N[React JS SOC Dashboard\nlocalhost:5173]
    end

    style A fill:#1e293b,stroke:#475569,stroke-width:2px,color:#fff
    style B fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#fff
    style Q fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff
    style E fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff
    style F fill:#312e81,stroke:#6366f1,stroke-width:2px,color:#fff
    style G fill:#701a75,stroke:#d946ef,stroke-width:2px,color:#fff
    style H fill:#831843,stroke:#ec4899,stroke-width:2px,color:#fff
    style N fill:#0e7490,stroke:#06b6d4,stroke-width:2px,color:#fff
```

---

## 2. Threat Triage & Scoring Model

Risk scores combine explainable rule severity with statistical anomaly detection, mapping directly into four operational action bands:

```mermaid
graph LR
    subgraph INPUTS ["Input Signals"]
        RS["Rule Points (0 - 35+)"]
        AS["Anomaly Score (0.0 - 1.0)"]
    end

    subgraph FORMULA ["Risk Score Formula"]
        F["Risk Score = 5.0 + (w_rule * ScaledRule + w_anom * ScaledAnom) * 45.0"]
    end

    subgraph BANDS ["Risk Bands (5.0 - 50.0)"]
        CRIT["🔴 Critical (42.0 - 50.0)\nImmediate Session Revocation & Escalation"]
        HIGH["🟠 High (30.0 - 41.9)\nTargeted Investigation & DLP Review"]
        MED["🟡 Medium (15.0 - 29.9)\nPolicy Tuning & Authentication Audit"]
        LOW["🟢 Low (5.0 - 14.9)\nStandard Operational Baseline"]
    end

    RS --> F
    AS --> F
    F --> CRIT
    F --> HIGH
    F --> MED
    F --> LOW

    style CRIT fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fff
    style HIGH fill:#431407,stroke:#f97316,stroke-width:2px,color:#fff
    style MED fill:#422006,stroke:#eab308,stroke-width:2px,color:#fff
    style LOW fill:#022c22,stroke:#10b981,stroke-width:2px,color:#fff
```

---

## 3. Key Features & Engineering Invariants

| Feature / Invariant | Implementation Mechanism | Verification Guarantee |
|---|---|---|
| **Strict 5.0–50.0 Range** | `backend/src/risk_normalizer.py` | Bounded dynamic scaling with hard clamping at 5.0 and 50.0. Tested via unit tests. |
| **Isolation Forest ML** | `backend/src/anomaly_scorer.py` | Unsupervised contamination fitting with `FALLBACK_RULE_ONLY` safety switch on small samples. |
| **Random Selection Control** | `backend/src/baseline.py` | Fixed-seed chance baseline sampling from identical entity pool to validate ML prioritization lift. |
| **Row-Level Quarantine** | `backend/src/ingestion.py` | Corrupted rows (missing fields, malformed dates) quarantined to log without halting scoring. |
| **SOC Dashboard** | `frontend/src/App.jsx` | Dark-theme command UI, entity deep-dive modal, baseline overlap charts, and what-if parameter sliders. |
| **Evidence Export** | `backend/src/pipeline.py` | Deterministic assessment exports to audit-ready JSON and CSV formats. |

---

## 4. Rule Catalog & Mitigation Playbook

| Rule Identifier | Indicator Pattern | Severity Points | Trigger Threshold | Automated Mitigation Recommendation |
|---|---|---|---|---|
| `R_PRIV_ESCALATION` | Unauthorized Privilege Escalation | Up to +15.0 | $\ge 1$ admin role grant | Urgent IAM privilege audit against change management tickets |
| `R_DATA_EXFIL` | Mass Data Transfer Spike | Up to +15.0 | $\ge 25\text{ MB}$ total / $15\text{ MB}$ single | Network DLP analysis & outbound connection inspection |
| `R_FAILED_LOGINS` | Authentication Failure Burst | Up to +12.0 | $\ge 3$ failures / $\ge 50\%$ ratio | Force MFA challenge, step-up auth, session revocation |
| `R_FW_DENIED` | Firewall Policy Denial Spike | Up to +10.0 | $\ge 3$ denied packets | Ingress/egress ACL tuning & perimeter IP block |
| `R_CONFIG_CHANGE` | Critical System Config Modification | Up to +10.0 | $\ge 2$ configuration edits | Configuration baseline diff & authorization review |
| `R_ODD_HOURS` | Anomalous Off-Hours Activity | Up to +8.0 | $\ge 4$ events outside 07:00-19:00 | Off-shift credential validation & emergency ticket audit |
| `R_DISTRIBUTED_IP` | Multi-Source IP Access Spread | Up to +8.0 | $\ge 4$ distinct IPs | Impossible travel evaluation & IP subnet restriction |

---

## 5. Project Directory Structure

```
P-006/
├── backend/
│   ├── data/
│   │   ├── generate_demo_data.py   # Synthetic security telemetry generator
│   │   ├── security_events.json    # Standard JSON demo dataset
│   │   └── security_events.csv     # Standard CSV demo dataset
│   ├── src/
│   │   ├── api/
│   │   │   └── server.py           # FastAPI REST endpoints
│   │   ├── schema.py               # Data models, validation contracts & bounds
│   │   ├── ingestion.py            # File ingestion & row quarantine
│   │   ├── feature_builder.py      # Entity behavioral feature extraction
│   │   ├── rule_engine.py          # Domain rule catalog & score extraction
│   │   ├── anomaly_scorer.py       # Isolation Forest scoring & fallback
│   │   ├── baseline.py             # Random Selection baseline generator
│   │   ├── risk_normalizer.py      # Bounded [5.0, 50.0] normalization
│   │   ├── recommendations.py      # Actionable remediation advice engine
│   │   └── pipeline.py             # Pipeline orchestrator & file exporter
│   ├── tests/
│   │   └── test_invariants.py      # Pytest automated invariant suite
│   ├── cli.py                      # Command-line assessment tool
│   └── requirements.txt            # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # React SOC Dashboard application
│   │   ├── index.css               # Dark theme design system
│   │   └── main.jsx                # React application entry point
│   ├── package.json                # Frontend dependencies
│   └── vite.config.js              # Vite configuration
├── start_system.ps1                # One-click startup script (PowerShell)
├── PRD.md                          # Product Requirements Document
├── ARCHITECTURE.md                 # System Architecture Baseline
├── PROGRESS.md                     # Implementation Progress Log
└── README.md                       # Master Documentation
```

---

## 6. Quickstart Guide

### Prerequisites
- **Python 3.10+**
- **Node.js 18+ & npm**

### 1. One-Click Launch (PowerShell)
```powershell
.\start_system.ps1
```
*Starts the FastAPI backend on `http://127.0.0.1:8000` and launches the React dashboard on `http://127.0.0.1:5173`.*

---

### 2. Manual Service Setup

**A. Backend API:**
```bash
pip install -r backend/requirements.txt
python -m uvicorn backend.src.api.server:app --host 127.0.0.1 --port 8000
```

**B. Frontend Dashboard:**
```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

**C. CLI Batch Assessment:**
```bash
python backend/cli.py --file backend/data/security_events.json --seed 42
```

---

## 7. REST API Reference

| HTTP Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status. |
| `GET` | `/api/assessment/latest` | Retrieve current assessment results with entity rankings. |
| `POST` | `/api/assessment/run` | Trigger dynamic re-scoring with custom weights, seed, or contamination. |
| `POST` | `/api/assessment/upload` | Upload custom CSV/JSON event file and compute risk scores. |
| `GET` | `/api/assessment/export/csv` | Download assessment report as CSV. |
| `GET` | `/api/assessment/export/json` | Download full assessment payload as JSON. |

*Interactive Swagger UI available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).*

---

## 8. Automated Test Suite

Run the full invariant test harness:
```bash
pytest backend/tests/ -v
```

```text
backend/tests/test_invariants.py::test_invariant_1_score_bounds_and_validity PASSED
backend/tests/test_invariants.py::test_invariant_2_entity_id_integrity PASSED
backend/tests/test_invariants.py::test_invariant_3_high_risk_explanation_coverage PASSED
backend/tests/test_invariants.py::test_invariant_4_baseline_population_alignment PASSED
backend/tests/test_invariants.py::test_invariant_5_row_quarantine_resilience PASSED
backend/tests/test_invariants.py::test_invariant_6_reproducibility_with_seed PASSED
backend/tests/test_invariants.py::test_extreme_score_clamping PASSED
backend/tests/test_invariants.py::test_empty_dataset_graceful_handling PASSED

============================== 8 passed ==============================
```

---

<p align="center">
  <sub>Built for IBM Problem Statement P-006: Predictive Risk Scoring Assessment</sub>
</p>
