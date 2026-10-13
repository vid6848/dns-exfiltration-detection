# CyberTrace Technical Code Reviews Index

This directory contains code reviews conducted by **Soham** (Project Coordination & Integration, `soham.prajapati24@spit.ac.in`) for all merged pull requests (#1–#5) and open remediation branches in `vid6848/dns-exfiltration-detection`.

---

## 1. Open Branch Reviews

| Branch | Author | Focus Area | Status | Review Document |
|---|---|---|---|---|
| `fix/backend-frontend-remediation` | Param (`param7862989-ops`) | CORS, `/analyze` chronological sort & index restoration, API and frontend test suites | **Approved for Integration** | [Param Remediation Review](param-remediation.md) |

---

## 2. Post-Hoc Reviews of Merged Pull Requests (#1–#5)

| PR # | Title & Author | Focus Area | Key Findings | Review Document |
|---|---|---|---|---|
| **#1** | Synthetic DNS Exfiltration Dataset v0.1<br>*(Param)* | Attack dataset generator, Base32/64/hex patterns, 10-column schema | Diverse attack pacing; column name mismatch addressed by preprocessing; unit test suite gap. | [PR #1 Review](PR-1.md) |
| **#2** | Preprocessing, Normalization & Leakage Prevention<br>*(Yash)* | Schema normalizer, FQDN parser, timestamp handling, leakage assertions | Excellent leakage guardrails; missing top-level `requirements.txt` broke project reproduction instructions. | [PR #2 Review](PR-2.md) |
| **#3** | Model Evaluation & Latency Benchmarks<br>*(Harshul)* | Baseline vs RF comparison, diagnostic 45,240 records, latency analysis | Honest diagnostic labeling; unresolved `source_hashes_match` investigation left for integration; sample size caveats in latency measurements. | [PR #3 Review](PR-3.md) |
| **#4** | FastAPI Inference & Batch Analysis<br>*(Pranay)* | `/predict`, `/analyze`, model bundle lifespan loading | Model loaded once on startup; **bug confirmed**: behavioral extractor re-instantiated inside batch loop; missing CORS; omitted 3 required endpoints (`/alerts`, `/statistics`, `/model-performance`). | [PR #4 Review](PR-4.md) |
| **#5** | React Dashboard Frontend<br>*(Bhumit)* | Interactive single/batch forms, dark cards, telemetry | Clean modular UI; static un-wired placeholders (`LiveAlertsTable`, `LiveStatsCards`); missing CSV upload flow; missing `npm test` script. | [PR #5 Review](PR-5.md) |

---

## 3. Integration & Remediation Action Plan
All identified gaps and missing requirements are addressed directly on the integration branch `integration/soham-e2e`:
1. Incorporate Param's batch sorting and CORS fix.
2. Complete all missing API endpoints: `GET /alerts`, `GET /statistics`, `GET /model-performance`, and multipart `POST /analyze/csv`.
3. Provide authoritative data contracts in `docs/CONTRACTS.md`.
4. Connect frontend components to live endpoints with robust loading and error states.
5. Create top-level `requirements.txt` and developer automation (`Makefile`).
6. Deliver end-to-end regression tests (`tests/test_contracts.py`, `tests/test_e2e.py`).
