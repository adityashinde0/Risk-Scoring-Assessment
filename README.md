# P-006 Predictive Risk Scoring Assessment

> **Dynamic Insider Threat Scoring (5–50 Scale) with Unsupervised Isolation Forest, Explainable Rule Signal Extraction, Random Selection Baseline, and React SOC Dashboard.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18%2B-61DAFB.svg)](https://react.dev/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Isolation--Forest-F7931E.svg)](https://scikit-learn.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-8%2F8%20Passing-brightgreen.svg)](https://pytest.org/)

---

## 📖 Table of Contents
- [Overview](#-overview)
- [Key Features & Invariants](#-key-features--invariants)
- [Architecture & Flow](#-architecture--flow)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running Tests](#running-tests)
  - [Launching the Application](#launching-the-application)
- [API Reference](#-api-reference)
- [Baseline & Evaluation](#-baseline--evaluation)
- [Contributing & Development](#-contributing--development)

---

## 🚀 Overview

**P-006 Predictive Risk Scoring Assessment** is a local, reproducible cyber security platform designed to identify and prioritize insider threats.

The system ingests raw authentication, file access, privilege modification, and network telemetry, computes granular behavioral indicators, fits an unsupervised **Isolation Forest** model to detect statistical anomalies, applies an explainable domain rule catalog, and normalizes scores strictly into a **5.0 to 50.0** risk range.

### System Workflow:
```
Raw Events (CSV/JSON)
       │
       ▼
[Schema Validation & Quarantine] ───► Invalid Rows Quarantined (Zero Crash)
       │
       ▼ (Valid Events)
[Entity Feature Aggregation]
       │
   ┌───┴──────────────────────────────┐
   ▼                                  ▼
[Rule / Pattern Engine]    [Isolation Forest Scorer]
   │                                  │
   └──────────────┬───────────────────┘
                  ▼
   [Risk Normalization (5.0 - 50.0)]
                  │
   ┌──────────────┴───────────────────┐
   ▼                                  ▼
[Random Selection Baseline]   [Recommendation Engine]
   │                                  │
   └──────────────┬───────────────────┘
                  ▼
   [Dashboard REST API & React SOC UI]
```

---

## ✨ Key Features & Invariants

1. **Strict Score Normalization ($5.0 \le \text{Score} \le 50.0$)**:
   - Enforces dynamic risk scoring mapped into distinct risk bands: `Low` (5–14), `Medium` (15–29), `High` (30–41), and `Critical` (42–50).
2. **Unsupervised Isolation Forest ML**:
   - Outlier isolation across high-dimensional behavioral feature vectors with automatic fallback protection (`FALLBACK_RULE_ONLY`) if data size is below fit threshold.
3. **Transparent Rule & Pattern Signals**:
   - Explicit domain indicators: Burst Failed Logins, Off-Hours Access, Privilege Escalations, Mass Data Exfiltration, and Firewall Denials.
4. **Random Selection Baseline & Control**:
   - Deterministic chance-level comparison with fixed seed to prove whether ML prioritization outperforms random sampling.
5. **Actionable Analyst Recommendations**:
   - Human-reviewed remediation steps (IAM privilege audit, session token revocation, DLP egress inspection, firewall rule tuning) mapped directly to risk contributors.
6. **Data Resilience & Row Quarantine**:
   - Corrupted timestamps, missing required fields, or malformed records are safely quarantined with detailed diagnostic error logs without aborting assessment of valid records.
7. **Modern React JS SOC Analyst Dashboard**:
   - High-contrast cybersecurity command interface with real-time what-if weight adjustments, entity deep-dive drawers, baseline candidate comparison, and JSON/CSV artifact exports.

---

## 📂 Project Structure

```
P-006/
├── backend/
│   ├── data/
│   │   ├── generate_demo_data.py   # Synthetic security event generator
│   │   ├── security_events.json    # Demo JSON event logs
│   │   └── security_events.csv     # Demo CSV event logs
│   ├── src/
│   │   ├── api/
│   │   │   └── server.py           # FastAPI REST endpoints
│   │   ├── schema.py               # Pydantic models & validation contracts
│   │   ├── ingestion.py            # File loading & row quarantine
│   │   ├── feature_builder.py      # Behavioral feature extraction
│   │   ├── rule_engine.py          # Domain rule catalog & score extraction
│   │   ├── anomaly_scorer.py       # Isolation Forest scoring & fallback
│   │   ├── baseline.py             # Random Selection baseline logic
│   │   ├── risk_normalizer.py      # 5.0 - 50.0 score normalization & bands
│   │   ├── recommendations.py      # Actionable mitigation engine
│   │   └── pipeline.py             # Full assessment coordinator & exporter
│   ├── tests/
│   │   └── test_invariants.py      # Automated invariant test suite (pytest)
│   ├── cli.py                      # Batch CLI runner
│   └── requirements.txt            # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # React SOC Dashboard application
│   │   ├── index.css               # SOC dark theme tokens & styling
│   │   └── main.jsx                # React root mount
│   ├── package.json                # Frontend dependencies
│   └── vite.config.js              # Vite bundler configuration
├── start_system.ps1                # PowerShell one-click startup script
├── PRD.md                          # Product Requirements Document
├── ARCHITECTURE.md                 # Technical Architecture Specification
├── PROGRESS.md                     # Implementation Progress & Status
└── README.md                       # Project Documentation
```

---

## 🛠️ Getting Started

### Prerequisites
- **Python 3.10+**
- **Node.js 18+ & npm**

---

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd P-006
   ```

2. **Install Backend Dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Install Frontend Dependencies:**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

---

### Running Tests

Run the automated test suite to verify all engineering invariants:
```bash
pytest backend/tests/ -v
```

Expected output:
```
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

### Launching the Application

#### Option A: One-Click Startup (PowerShell)
```powershell
.\start_system.ps1
```

#### Option B: Manual Service Launch

1. **Start Backend API Server:**
   ```bash
   python -m uvicorn backend.src.api.server:app --host 127.0.0.1 --port 8000
   ```

2. **Start Frontend Dev Server:**
   ```bash
   cd frontend
   npm run dev -- --host 127.0.0.1 --port 5173
   ```

3. **Access Endpoints:**
   - **SOC Dashboard**: [http://127.0.0.1:5173/](http://127.0.0.1:5173/)
   - **Interactive API Documentation (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

### CLI Batch Assessment

You can also run batch risk scoring directly from the command line:
```bash
python backend/cli.py --file backend/data/security_events.json --seed 42 --rule-weight 0.60 --anomaly-weight 0.40
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check endpoint. |
| `GET` | `/api/assessment/latest` | Retrieve current assessment run. |
| `POST` | `/api/assessment/run` | Trigger re-scoring with custom weights, seed, and review rate. |
| `POST` | `/api/assessment/upload` | Upload custom CSV/JSON event log file and compute risk scores. |
| `GET` | `/api/assessment/export/csv` | Download assessment report as CSV. |
| `GET` | `/api/assessment/export/json` | Download complete assessment output as JSON. |

---

## 🔬 Baseline & Evaluation

To adhere to scientific rigor, the system uses a **Random Selection Baseline** with fixed seed reproducibility:
- Randomly samples entities from the identical principal population at a configurable review rate (e.g. 25%).
- Computes chance overlap against high-risk entities identified by Machine Learning and Rules.
- Enables SOC managers to defend why ML-assisted prioritization provides superior threat coverage over randomized sampling.

---

## 🔒 Security & Safe Remediation Notice

- **No Automated Execution**: Recommendations are intended for human review and authorization by security analysts.
- **Local-First Processing**: Logs and features are processed locally without unauthorized external data transmission.
