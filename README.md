# P-006: Predictive Risk Scoring Assessment

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/React-18.x-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/scikit--learn-Isolation_Forest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Vite-6.x-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Pytest-17%2F17%20Passed-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" alt="Pytest" />
</p>

<p align="center">
  <strong>Dynamic insider-threat scoring (5.0–50.0 scale) combining unsupervised Isolation Forest anomaly detection, explainable rule extraction, deterministic Random Selection control, and a real-time SOC analyst dashboard.</strong>
</p>

---

## 📑 Table of Contents
- [1. Architecture & System Flow](#1-architecture--system-flow)
- [2. Threat Triage & Scoring Model](#2-threat-triage--scoring-model)
- [3. Key Features & Engineering Invariants](#3-key-features--engineering-invariants)
- [4. Multi-Method Benchmark Evaluation](#4-multi-method-benchmark-evaluation)
- [5. Rule Catalog & Mitigation Playbook](#5-rule-catalog--mitigation-playbook)
- [6. Project Directory Structure](#6-project-directory-structure)
- [7. Quickstart Guide](#7-quickstart-guide)
- [8. REST API Reference](#8-rest-api-reference)
- [9. Automated Test Suite](#9-automated-test-suite)
- [10. Scope & Limitations](#10-scope--limitations)

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
| **Strict 5.0–50.0 Range** | `backend/src/risk_normalizer.py` | Hard mathematical clamping at 5.0 and 50.0. Tested via automated invariant tests. |
| **Dynamic Score Adaptation** | `backend/src/pipeline.py` | Multi-window recalculation comparing current window against baseline with delta ($\Delta$) tracking. |
| **Isolation Forest ML** | `backend/src/anomaly_scorer.py` | Unsupervised contamination fitting with `FALLBACK_RULE_ONLY` safety switch on small samples. |
| **Random Selection Control** | `backend/src/baseline.py` | Fixed-seed chance baseline sampling from identical entity pool to validate ML prioritization lift. |
| **Row-Level Quarantine** | `backend/src/ingestion.py` | Corrupted rows (missing fields, malformed dates) quarantined to log without halting scoring. |
| **SOC Dashboard** | `frontend/src/App.jsx` | Dark-theme command UI, entity deep-dive modal, baseline overlap charts, and what-if parameter sliders. |
| **Evidence Export** | `backend/src/pipeline.py` | Deterministic assessment exports to audit-ready JSON and CSV formats. |

---

## 4. Multi-Method Benchmark Evaluation

To avoid ungrounded claims, the repository includes an automated evaluation harness (`backend/benchmark.py` and `GET /api/assessment/evaluation`) that compares four candidate prioritization strategies on labeled scenario data:

> **Evaluation Disclaimer**: Results are measured on labeled synthetic insider threat demo scenarios to demonstrate algorithmic lift over random review under controlled conditions. These are evaluation benchmarks and do not constitute unverified real-world production cybersecurity accuracy.

### Benchmark Results Matrix:

| Prioritization Strategy | Precision | Recall | F1 Score | False Positive Rate | Threat Capture Rate |
|---|---|---|---|---|---|
| **Combined Dynamic Risk (P-006)** | **100.0%** | **75.0%** | **0.86** | **0.0%** | **75.0%** |
| **Rule-Only Signal Engine** | 100.0% | 100.0% | 1.00 | 0.0% | 100.0% |
| **Isolation Forest ML** | 80.0% | 100.0% | 0.89 | 5.9% | 100.0% |
| **Random Selection Baseline** | 20.0% | 25.0% | 0.22 | 23.5% | 25.0% |

Run the benchmark CLI directly:
```bash
python backend/benchmark.py --file backend/data/security_events.json --seed 42
```

---

## 5. Rule Catalog & Mitigation Playbook

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

## 6. Project Directory Structure

```
P-006/
├── backend/
│   ├── data/
│   │   ├── generate_demo_data.py                    # Multi-window telemetry generator
│   │   ├── security_events_window1_baseline.json    # Window 1: Normal baseline
│   │   ├── security_events_window2_threats.json     # Window 2: Threat incident
│   │   ├── security_events.json                     # Default evaluation dataset
│   │   └── security_events.csv                      # Default CSV dataset
│   ├── src/
│   │   ├── api/
│   │   │   └── server.py           # FastAPI REST endpoints & swagger
│   │   ├── schema.py               # Data models, validation contracts & bounds
│   │   ├── ingestion.py            # File ingestion & row quarantine
│   │   ├── feature_builder.py      # Entity behavioral feature extraction
│   │   ├── rule_engine.py          # Domain rule catalog & score extraction
│   │   ├── anomaly_scorer.py       # Isolation Forest scoring & fallback
│   │   ├── baseline.py             # Random Selection baseline generator
│   │   ├── evaluation.py           # Multi-method evaluation & metrics
│   │   ├── risk_normalizer.py      # Bounded [5.0, 50.0] normalization
│   │   ├── recommendations.py      # Actionable remediation advice engine
│   │   └── pipeline.py             # Pipeline orchestrator & file exporter
│   ├── tests/
│   │   └── test_invariants.py      # Pytest automated invariant suite (17 tests)
│   ├── cli.py                      # Command-line assessment tool
│   ├── benchmark.py                # Command-line evaluation runner
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

## 7. Quickstart Guide

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

## 8. REST API Reference

| HTTP Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status. |
| `GET` | `/api/assessment/latest` | Retrieve current assessment results with entity rankings. |
| `GET` | `/api/assessment/entities/{entity_id}` | Retrieve individual entity deep-dive record. |
| `GET` | `/api/assessment/evaluation` | Retrieve 4-method comparative benchmark metrics. |
| `POST` | `/api/assessment/run` | Trigger dynamic re-scoring with custom weights, window, seed, or contamination. |
| `POST` | `/api/assessment/upload` | Upload custom CSV/JSON event file and compute risk scores. |
| `GET` | `/api/assessment/export/csv` | Download assessment report as CSV. |
| `GET` | `/api/assessment/export/json` | Download full assessment payload as JSON. |

*Interactive Swagger UI available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).*

---

## 9. Automated Test Suite

Run the full invariant test harness:
```bash
pytest backend/tests/ -v
```

```text
backend/tests/test_invariants.py::test_csv_ingestion_and_metadata_parsing PASSED
backend/tests/test_invariants.py::test_evaluation_benchmark_metrics PASSED
backend/tests/test_invariants.py::test_gradient_threat_sensitivity PASSED
backend/tests/test_invariants.py::test_invariant_4_baseline_population_alignment PASSED
backend/tests/test_invariants.py::test_invariant_5_row_quarantine_resilience PASSED
backend/tests/test_invariants.py::test_empty_csv_file_graceful_handling PASSED
backend/tests/test_invariants.py::test_invariant_3_high_risk_explanation_coverage PASSED
backend/tests/test_invariants.py::test_empty_dataset_graceful_handling PASSED
backend/tests/test_invariants.py::test_invariant_6_reproducibility_with_seed PASSED
backend/tests/test_invariants.py::test_invariant_1_score_bounds_and_validity PASSED
backend/tests/test_invariants.py::test_score_sensitivity_to_threat_injection PASSED
backend/tests/test_invariants.py::test_dynamic_window_score_shift PASSED
backend/tests/test_invariants.py::test_benign_unusual_entity_non_threat PASSED
backend/tests/test_invariants.py::test_invariant_2_entity_id_integrity PASSED
backend/tests/test_invariants.py::test_api_endpoints_integration PASSED
backend/tests/test_invariants.py::test_extreme_score_clamping PASSED
backend/tests/test_invariants.py::test_recommendation_linkage_to_contributors PASSED

============================== 17 passed in 11.19s ==============================
```

---

## 10. Scope & Limitations

- **Local Batch Architecture**: Ingests file-based CSV/JSON batches; not connected to live streaming Kafka clusters or production SIEM agents.
- **Controlled Evaluation Dataset**: Benchmark metrics are evaluated against synthetic insider threat patterns; real-world efficacy requires organizational telemetry.
- **Human-in-the-Loop Remediation**: System produces actionable recommendations; it intentionally avoids automated firewall block deployment to prevent disruptive false-positive outages.
