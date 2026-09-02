# PRD: P-006 Predictive Risk Scoring Assessment

## 1. Problem Definition

### Problem-statement facts

- Problem code: P-006.
- Domain: cyber security.
- Programming language requirement: Java/Python; the requested planning constraint fixes the MVP on Python.
- Stated technologies: Python, Machine Learning Models, Isolation Forest, Random Selection, React JS.
- Problem: insider threats are critical organizational challenges.
- Stated reason it matters: early identification helps prevent data breaches, minimize downtime, and avoid financial loss.
- Required outcome:
  - Assign dynamic risk scores to specific entities.
  - Identify and surface rules and patterns that most significantly impact each entity.
  - Dynamically determine risk scores in the range of 5 to 50 and assign them automatically.
  - Provide actionable recommendations such as adjusting configurations or tuning firewall rules.
  - Improve detection of true threats and reduce false positives through better scoring and recommendations.
- Key features:
  - Dynamic, data-driven risk scoring that adapts over time.
  - Better visibility into user and entity health.
  - Highlight which rules and patterns contribute most to risk.
  - Granular-level assessment and fine-tuned risk scoring for each rule.
  - Identify early threats so users can take timely action.

### Engineering judgment

The MVP should be a local, reproducible risk assessment system that ingests security/event telemetry, extracts per-entity behavioral features, computes rule-level signals, trains/applies Isolation Forest for anomaly scoring, compares it against Random Selection as a baseline/control, and presents ranked entity risk with contributing patterns and recommendations in a React dashboard.

### Assumptions

- "Entities" means users, hosts, service accounts, devices, or IP-like principals observable in security logs.
- No real organizational telemetry is supplied, so the MVP must support CSV/JSON sample data and a small synthetic/demo dataset for demonstration.
- "Random Selection" means a random baseline for choosing entities for review, not Random Forest. This is necessary because the problem statement says "Random Selection" under ML models.
- Risk scores must be integer or decimal values normalized to the required range of 5 to 50.
- The hackathon judges will value explainability, reproducibility, demo clarity, and measurable comparison against a baseline.

## 2. Core Value Proposition

The system turns raw security activity into prioritized, explainable insider-risk assessments. Security analysts can see which entities are currently highest risk, why they were scored that way, which rules/patterns contributed, and what first response actions are recommended.

The core value is not just anomaly detection. It is risk triage with transparent contributing factors and an explicit baseline so the team can defend whether the ML-assisted scoring is useful compared with random review.

## 3. Requirements

### Functional Requirements

| ID | Requirement | Source Discipline | Priority |
|---|---|---|---|
| F1 | Ingest entity activity data from local CSV/JSON files. | Assumption + engineering judgment | Must |
| F2 | Normalize activity into entity-level feature vectors. | Strongly implied by data-driven scoring | Must |
| F3 | Apply configurable rule/pattern detectors per entity. | Problem-statement fact | Must |
| F4 | Train or load an Isolation Forest model for anomaly scoring. | Problem-statement fact + official-source fact | Must |
| F5 | Compute a Random Selection baseline/control for review prioritization. | Problem-statement fact interpreted as baseline | Must |
| F6 | Convert anomaly/rule signals into risk scores in the range 5 to 50. | Problem-statement fact | Must |
| F7 | Surface top contributing rules/patterns for each entity. | Problem-statement fact | Must |
| F8 | Provide actionable recommendations for each high-risk entity. | Problem-statement fact | Must |
| F9 | Display entity rankings, score history, contributions, recommendations, and baseline comparison in React JS. | Problem-statement fact + engineering judgment | Must |
| F10 | Export assessment results as JSON/CSV for evidence and demo repeatability. | Engineering judgment | Should |
| F11 | Support analyst feedback labels for later evaluation, without requiring a full active-learning workflow. | Optional enhancement | Could |

### Non-Functional Requirements

| ID | Requirement | Rationale | Priority |
|---|---|---|---|
| NF1 | Local-first execution with no paid external APIs. | Operating constraint | Must |
| NF2 | Reproducible demo run from fixed sample data and fixed random seed. | Defensibility and judging | Must |
| NF3 | Explainability at rule and feature-summary level. | Problem requires surfaced rules/patterns | Must |
| NF4 | Graceful handling of malformed or missing input fields. | Security tool reliability | Must |
| NF5 | Clear separation between measured results and claims. | Source-grounding policy | Must |
| NF6 | Usable on a normal developer laptop without GPU. | 24-hour MVP feasibility | Must |
| NF7 | Simple, maintainable interfaces between ingestion, scoring, and UI. | Parallel team execution | Must |

### Constraints

| Constraint | Source Discipline |
|---|---|
| Use Python. | Problem-statement fact/requested technology constraint |
| Use Isolation Forest. | Problem-statement fact |
| Use Random Selection. | Problem-statement fact |
| Use React JS. | Problem-statement fact |
| 24-hour implementation window. | Operating context |
| Team of 3 implementation programmers + 1 external AI/research support member. | Operating context |
| Do not use paid external APIs/services unless strongly justified. | Operating context |
| Do not generate implementation code during planning. | User request |

### Evaluation Requirements

| Metric | Definition | Baseline |
|---|---|---|
| Risk score validity | 100% of produced risk scores are within 5-50 and tied to an entity. | Required invariant |
| Ranking usefulness | If labels are available, compare top-k precision/recall for Isolation Forest scoring vs Random Selection. | Random Selection |
| False-positive proxy | Count entities flagged high-risk without matching demo labels or analyst feedback. | Random Selection |
| Explanation completeness | Percentage of high-risk entities with at least one contributing rule/pattern and recommendation. | Required target: 100% for high-risk results |
| Runtime | Time to ingest, featurize, score, and return dashboard-ready results on demo data. | Measured only; no claim before implementation |
| Robustness | Malformed rows rejected or quarantined without breaking full assessment. | Required behavior |

## 4. Users / Actors

| Actor | Role |
|---|---|
| Security analyst | Reviews ranked entities, explanations, and recommendations. |
| SOC lead / security manager | Uses aggregate view to prioritize investigation capacity and understand trend risk. |
| System administrator / firewall operator | Applies or evaluates configuration and firewall recommendations. |
| Data source / log exporter | Provides authentication, access, endpoint, network, or firewall activity records. |
| ML scoring service | Computes anomaly and risk scores from prepared features. |
| Human reviewer | Provides validation labels or feedback for demo/evaluation if available. |

## 5. Assumptions

1. The MVP will not connect to production SIEM, EDR, IAM, or firewall systems; it will ingest local exported/sample data.
2. Recommendations will be rule-based and conservative, because automated firewall/configuration changes are too risky for a hackathon MVP.
3. The Isolation Forest model will be unsupervised or semi-supervised because insider-threat labels are unlikely to be available in hackathon data.
4. Score adaptation over time means recalculating features over sliding time windows and retraining or refreshing the model on newer batches, not building a streaming production pipeline.
5. Sensitive personal data should not be required for the demo; entity IDs can be pseudonymous.

## 6. MVP Scope

| Feature | Purpose | Requirement Satisfied | Judging Value | Owner |
|---|---|---|---|---|
| Local data ingestion and schema validation | Load CSV/JSON events safely and consistently | F1, NF4 | Shows reproducibility and reliability | Programmer 1 |
| Entity feature builder | Aggregate raw events into ML-ready per-entity features | F2 | Makes scoring technically credible | Programmer 1 |
| Rule/pattern signal engine | Detect visible risk contributors such as odd-hour access, failed login bursts, privilege changes, unusual data volume, sensitive resource access, and firewall-denied activity | F3, F7 | Gives explainability and domain fit | Programmer 1 |
| Isolation Forest scoring | Produce anomaly score component for each entity | F4, F6 | Satisfies required ML technology | Programmer 1 |
| Random Selection baseline | Randomly select comparable entities for review using fixed seed | F5 | Enables measurable comparison and honest claims | Programmer 2 |
| Risk normalization 5-50 | Convert model/rule signals into required risk range | F6 | Directly satisfies outcome | Programmer 1 |
| Recommendation engine | Map top contributors to analyst-safe remediation suggestions | F8 | Turns scores into action | Programmer 2 |
| Results API / local service boundary | Provide dashboard-ready assessment outputs | F9, F10 | Supports clean integration | Programmer 2 |
| React dashboard | Show ranked risks, entity details, contributors, recommendations, baseline comparison, and evidence export | F9, F10 | Makes demo understandable | Programmer 3 |
| Validation and demo harness | Verify score bounds, schema handling, baseline comparison, and reproducible demo flow | Evaluation requirements | Makes project defensible | Programmer 3 |

## 7. Out of Scope

- Production SIEM/EDR/IAM/firewall integrations.
- Automated blocking, account disabling, or firewall rule deployment.
- Real-time streaming infrastructure.
- User authentication and role-based access control beyond local demo constraints.
- Deep learning, LLMs, RAG, vector databases, or AI agents.
- Long-term model governance and full compliance workflow.
- Guaranteed accuracy improvement before evaluation.
- Full forensic case management.

## 8. Success Metrics

| Metric | MVP Target |
|---|---|
| Score range correctness | Every entity score is between 5 and 50. |
| Explanation coverage | Every high-risk entity has top contributors and at least one recommendation. |
| Baseline comparison | Dashboard shows Isolation Forest/rule ranking beside Random Selection using identical input population. |
| Reproducibility | Same sample data and seed produce the same baseline and score output, except for intentionally refreshed windows. |
| Data robustness | Invalid rows are reported without crashing the assessment. |
| Demo completion | End-to-end demo runs from data upload/sample selection to ranked entity detail within the local environment. |

No accuracy, precision, recall, or false-positive reduction claim should be made unless labels or reviewer feedback are available and measured.

## 9. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Insider-threat labels may be unavailable | Cannot prove detection accuracy | Use Random Selection baseline, labeled synthetic scenarios, and clearly mark results as demo evidence |
| Isolation Forest can flag statistical anomalies that are benign | False positives | Combine anomaly score with transparent rule contributors and recommendations for human review |
| "Random Selection" interpretation may be challenged | Judging risk | Document interpretation and implement it as a defensible baseline/control |
| Recommendations may be too generic | Reduced value | Tie recommendations to specific top contributors |
| Score normalization may appear arbitrary | Credibility risk | Define formula, bounds, and weights; treat weights as configurable MVP assumptions |
| Security/privacy concerns | Mishandling sensitive telemetry | Use local files, pseudonymous IDs, no external data transfer |
| Team merge conflicts | Slows 24-hour delivery | Use stable contracts: input schema, feature table, assessment output schema |

## 10. Demo Strategy

1. Start with sample insider-risk activity data containing normal entities and a small set of labeled suspicious scenarios.
2. Run the assessment locally.
3. Show the React dashboard ranked entity list with scores from 5 to 50.
4. Open one high-risk entity and show:
   - contributing rules/patterns,
   - Isolation Forest anomaly contribution,
   - recommended analyst actions,
   - score trend/window comparison.
5. Compare top-k review candidates against Random Selection using the same dataset.
6. Export the result file as evidence.
7. State only measured findings; avoid claiming true production accuracy from demo data.

## Evidence / Source Discipline

| Decision | Evidence / Source | Reason | Confidence |
|---|---|---|---|
| Use Isolation Forest for anomaly scoring | Problem requires it; scikit-learn documents IsolationForest as returning anomaly scores and isolating observations through random feature/split selection; Liu, Ting, and Zhou introduced Isolation Forest for anomaly detection. Sources: scikit-learn IsolationForest docs, IEEE ICDM 2008 paper. | Insider risk is likely sparse and labels may be unavailable, making anomaly detection appropriate for MVP triage. | High for technical suitability; medium for domain effectiveness until evaluated |
| Use Random Selection as baseline/control | Problem lists Random Selection; scikit-learn documents reproducible random splitting/selection behavior through random_state concepts. | Random baseline lets the team compare whether scoring prioritizes known demo risks better than chance. | Medium |
| Use log-derived behavioral features | CISA guidance says logging and monitoring help identify anomalies or unauthorized behavior; CERT/SEI discusses insider-threat data collection and anomaly indicators. | Risk scoring needs observable behavior signals, not only a black-box score. | High |
| Avoid automated remediation | Engineering judgment based on cybersecurity safety risk. | Recommendations are safer and easier to validate than automatic firewall/config changes in 24 hours. | Medium |

External sources used:

- scikit-learn IsolationForest documentation: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- Liu, Ting, Zhou, "Isolation Forest", IEEE ICDM 2008: https://doi.org/10.1109/ICDM.2008.17
- CISA logging and monitoring guidance: https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems
- CERT/SEI insider threat data collection and analysis: https://insights.sei.cmu.edu/blog/intp-series-data-collection-and-analysis-part-11-of-18/
