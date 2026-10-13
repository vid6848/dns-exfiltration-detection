# CyberTrace Integration, Architecture & End-to-End Delivery Report

**Project:** CyberTrace: DNS Exfiltration Detection Using Network Traffic Analysis  
**Repository:** `vid6848/dns-exfiltration-detection`  
**Author:** Soham Prajapati (GitHub: `@Soham-Prajapati`, Git Email: `soham.prajapati24@spit.ac.in`)  
**Assigned Area:** Project Coordination & Integration (API/data contracts, repo structure, PR reviews, integration branch, end-to-end demo, setup guide and integrated build)  
**Evaluation Scope:** Diagnostic Development Evaluation (Outer Fold 5) — Not an independent final test or production generalizability claim  
**Report Date:** 2026-10-13  
**Status:** Complete & Verified  

---

## 1. Executive Summary & Assigned Role Scope

Per the approved **CyberTrace Team Work Allocation** (`CyberTrace_Team_Work_Allocation.pdf`), my primary ownership as Project Coordination & Integration Lead comprises:
> *"Own task board, API and data contracts, repository structure, pull request reviews, integration branch, and end to end demo. Deliver setup guide and integrated build."*

Prior to this integration phase, the project consisted of separately delivered component pull requests (#1 through #5) merged into `main`, but lacked an operational end-to-end integration layer. Crucial endpoints were absent, batch behavioral feature extraction suffered from state-destruction bugs, CORS was not configured, the repository setup instructions failed out-of-the-box, and dashboard telemetry was entirely disconnected from backend inference.

On the dedicated integration branch `integration/soham-e2e`, I resolved all identified regressions, formalized authoritative contracts in `docs/CONTRACTS.md`, unified project dependencies and automation in `requirements.txt` and `Makefile`, completed the full 5-endpoint REST API suite plus multipart CSV processing in `api/main.py`, connected the React dashboard to live telemetry feeds, conducted exhaustive reviews of PRs #1–#5, investigated the root cause of `source_hashes_match = false`, established CI/CD and repository governance, and authored a reproducible demo guide (`docs/DEMO.md`).

---

## 2. Baseline Status at Handoff & Evidence of Gaps

An exhaustive audit of `main` at commit `8321f8a` and engineering handoff documentation (`HANDOFF_TO_PRANAY_AND_SOHAM.pdf`) revealed several integration gaps:

### 2.1 Broken Environment Reproduction (`requirements.txt`)
- **Evidence:** Running `pip install -r requirements.txt` as instructed in both the project documentation and the initial draft report failed immediately with:
  ```text
  ERROR: Could not open requirements file: [Errno 2] No such file or directory: 'requirements.txt'
  ```
- **Root Cause:** Dependencies were split across `requirements-data.txt`, `requirements-training.txt`, and `requirements-dev.txt`, with no top-level `requirements.txt` existing in the repository root.

### 2.2 Incomplete API Endpoint Implementation
- **Evidence:** In `api/main.py` (delivered in PR #4), only `GET /`, `GET /health`, `POST /predict`, and `POST /analyze` were defined.
- **Omissions:** The three required endpoints mandated in Handoff Section 4 were completely missing:
  1. `GET /alerts`: Required for live feed of suspicious activity.
  2. `GET /statistics`: Required for real aggregated traffic counts.
  3. `GET /model-performance`: Required to dynamically serve offline benchmark figures.
  4. `POST /analyze/csv`: Missing multipart CSV file upload capability.

### 2.3 Batch Behavioral Extractor Re-Instantiation Bug (Confirmed)
- **Evidence:** In PR #4 (`api/main.py:139-142`):
  ```python
  for query in batch.queries:
      ...
      # Fresh behavioral context for this query.
      behavioral_extractor = BehavioralFeatureExtractor(window_seconds=60.0)
      behavioral_features = behavioral_extractor.extract(record)
      features.update(behavioral_features)
  ```
- **Impact:** Re-instantiating the extractor inside the loop destroyed sliding-window history between queries. Every single query was treated as the first query (`time_interval = -1.0`, `query_frequency = 1.0`, `unique_subdomains = 1.0`), preventing multi-query burst detection. Furthermore, incoming queries were not sorted chronologically.

### 2.4 Missing CORS Middleware & Zero API Automated Tests
- **Evidence:** PR #4 contained zero CORS middleware, causing browser requests from the Vite dashboard on port 3000 to be blocked by browser CORS policy. PR #4 was merged without a single unit test (`tests/test_api.py` did not exist).

### 2.5 Unwired Frontend Placeholders
- **Evidence:** In `frontend/src/` (delivered in PR #5):
  - `LiveStatsCards.jsx`: Rendered hardcoded static placeholder strings (`--`).
  - `LiveAlertsTable.jsx`: Completely disconnected from `/predict` and `/analyze`; remained static even when attacks were flagged.
  - `OfflineModelPerformance.jsx`: Loaded hardcoded static constants from a local file (`offlineEvaluationData.js`) rather than consuming the backend API.
  - `package.json`: Lacked a `"test"` script, causing `npm test` to fail immediately.

---

## 3. Work Delivered on `integration/soham-e2e`

Every contribution was delivered through small, conventional commits adhering strictly to the project rules:

| Commit Hash | Commit Message | Files Added / Modified | Description & Technical Rationale |
|---|---|---|---|
| `be83592` | `docs(reviews): add review of Param remediation branch and post-hoc reviews for PRs #1-#5` | `docs/reviews/param-remediation.md`, `PR-1.md` through `PR-5.md`, `README.md` | Formal technical code reviews for open remediation branch and all merged PRs. |
| `09eb495` | `Merge branch 'origin/fix/backend-frontend-remediation' into integration/soham-e2e` | `api/main.py`, `tests/test_api.py`, `frontend/package.json`, `client.test.js` | Merged approved remediation branch adding CORS, chronological batch sorting, and baseline API tests. |
| `168e82c` | `docs(contracts): add authoritative API and data contracts specification` | `docs/CONTRACTS.md` | Defined authoritative schemas, 10-feature manifest, 0.89 threshold, capture-isolation, and terminology policies. |
| `75bf8be` | `build: add unified requirements.txt and workflow Makefile` | `requirements.txt`, `Makefile` | Resolved the broken reproduction step by consolidating all requirements and automating `setup`, `test`, `verify`, `api`, `web`, and `demo`. |
| `9569245` | `feat(api): implement /analyze/csv, /alerts, /statistics, /model-performance and contract test suite` | `api/main.py`, `tests/test_contracts.py`, `tests/test_e2e.py` | Built the remaining API suite with in-memory telemetry, multipart CSV parsing, and added 11 contract/e2e regression tests. |
| `6391739` | `feat(frontend): integrate live telemetry, alerts feed, CSV upload and model performance` | `frontend/src/App.jsx`, `BatchAnalysisForm.jsx`, `LiveStatsCards.jsx`, `LiveAlertsTable.jsx`, `OfflineModelPerformance.jsx`, `TrafficTimelinePlaceholder.jsx`, `client.js`, `client.test.js` | Wired all placeholder components to live API endpoints, added CSV file upload with tab switcher, and expanded client tests to 8 passed tests. |
| `af022b5` | `ci: add GitHub Actions workflow, PR template, CODEOWNERS, and CONTRIBUTING guide` | `.github/workflows/ci.yml`, `.github/pull_request_template.md`, `CODEOWNERS`, `CONTRIBUTING.md` | Established CI pipeline running pytest, model verification, frontend test/build, and formal repository governance. |
| `f58426e` | `docs(provenance): document root cause of source_hashes_match newline divergence` | `docs/provenance_investigation.md` | Discovered and documented the CRLF vs LF root cause of source hash divergence without tampering with metadata. |
| `ef0ad9a` | `docs(demo): add reproducible end-to-end demonstration guide` | `docs/DEMO.md` | Step-by-step reproducible walkthrough covering setup, execution, single queries, CSV upload, and telemetry verification. |

---

## 4. Authoritative Contracts & System Architecture

Full specification documented in `docs/CONTRACTS.md`:

### 4.1 Request & Response Contract Overview
- **Endpoints:**
  - `POST /predict`: Ingests single DNS query event. Returns prediction, integer label (`0` or `1`), neutral `attack_score`, operating `threshold` (0.89), `risk_label`, rule indicators, and `alert_id`.
  - `POST /analyze`: Ingests JSON batch of up to 1,000 queries. Sorts chronologically by epoch, isolates history per batch, and returns itemized results in original request order.
  - `POST /analyze/csv`: Accepts multipart `.csv` files up to 15MB / 20,000 rows. Normalizes through canonical `src/preprocessing/pipeline.py`.
  - `GET /alerts`: Returns real suspicious events in reverse chronological order with stable alert IDs (`alt_xxxxxxxxxxxx`).
  - `GET /statistics`: Returns real cumulative telemetry counts (`total_processed`, `total_suspicious`, `total_benign`, `suspicious_rate`).
  - `GET /model-performance`: Serves verified benchmark results from `evaluation/results/baseline_vs_rf_v1/baseline_vs_rf_metrics.json` labeled `"diagnostic/development evaluation, not independent final test"`.
- **Operating Decision Threshold:** Calibrated at $\tau = 0.89$.
- **Terminology Directive:** Tree vote probability is strictly termed `attack_score`, **never** "confidence" or "calibrated confidence".

### 4.2 Data Leakage Guardrails & Feature Ordering
In accordance with `src/preprocessing/schema.py:verify_ml_feature_safety`, metadata fields (`src_ip`, `dst_ip`, `timestamp`, `requested_server_name`, `label`, `source`) are strictly barred from entering the feature vector. The Random Forest classifier enforces the exact ten-feature manifest:
1. `query_length` (Lexical)
2. `longest_label_length` (Lexical)
3. `number_of_labels` (Lexical)
4. `entropy` (Lexical Shannon Entropy)
5. `digit_ratio` (Lexical)
6. `special_char_ratio` (Lexical)
7. `subdomain_length` (Lexical)
8. `query_frequency` (Sliding Window Behavioral, 60s)
9. `unique_subdomains` (Sliding Window Behavioral, 60s)
10. `time_interval` (Behavioral $\Delta t$, initial query = -1.0)

---

## 5. Technical Reviews Summary

Exhaustive reviews were authored and saved under `docs/reviews/`:

1. **Param's Remediation Branch (`docs/reviews/param-remediation.md`):**
   - Verified that chronological sorting on `epoch_time` followed by stable index mapping restores input order while maintaining valid sliding-window state. Verified CORS origin configuration.
2. **PR #1 (Synthetic Attack Dataset, `docs/reviews/PR-1.md`):**
   - Praised multi-pattern generation (Base32/64/hex, burst vs drip) and private IP blending (`10.0.30.186`); noted column name discrepancies reconciled by preprocessing.
3. **PR #2 (Preprocessing & Normalization, `docs/reviews/PR-2.md`):**
   - Highlighted strict data leakage assertions; noted the missing root `requirements.txt`.
4. **PR #3 (Model Evaluation, `docs/reviews/PR-3.md`):**
   - Commended fair side-by-side comparison on 45,240 diagnostic records; identified unresolved `source_hashes_match` and missing API serving endpoint.
5. **PR #4 (FastAPI Backend, `docs/reviews/PR-4.md`):**
   - Commended startup lifespan bundle loading; confirmed the critical behavioral extractor re-instantiation bug inside `/analyze`, absence of CORS, and omission of `/alerts`, `/statistics`, and `/model-performance`.
6. **PR #5 (React Dashboard, `docs/reviews/PR-5.md`):**
   - Commended clean dark-mode UI; noted placeholder components were unwired and `npm test` script was missing.

---

## 6. Investigation: Root Cause of `source_hashes_match = false`

Full investigation documented in `docs/provenance_investigation.md`:

### 6.1 Findings
- Integrity checks in `scripts/summarize_aws_expansion.py` hash source files against recorded digests in `artifacts/aws_benign_expansion_v0.1/experiment.json['source_sha256']`.
- Comparing hashes showed that files in `src/ml/` matched perfectly, but files in `src/features/` and `src/preprocessing/` did not.
- Inspecting `src/features/per_query.py` showed zero git modifications since commit `88d34a3` by Harsh Vishwakarma.
- Replacing Unix LF (`\n`) line endings with Windows CRLF (`\r\n`) produced an **exact, character-for-character match** with the recorded hash:
  - LF hash: `cb97a101b004d331f2cd4dc5887a18bda27a2d6f353ad67cf50f2f5d49240019`
  - CRLF hash: `bf921fc0c49b0c38bda451903adc168536f812082e458f0025d751d15cbae71f` (Recorded in `experiment.json`)
- **Conclusion:** Preprocessing and feature engineering modules were authored on Windows where git checked them out with CRLF endings. When the training experiment script hashed the files in binary mode, it hashed the CRLF bytes. On Unix checkouts (LF), binary hashing diverges. **The underlying code semantics are 100% identical. No metadata was modified to artificially suppress the warning.**

---

## 7. End-to-End Acceptance Checklist (Handoff Section 5)

| Checklist Item | Requirement | Completion Evidence & Verification |
|---|---|---|
| **Single event** | One DNS event returns a prediction using the saved 0.89 decision threshold. | Verified via `test_e2e_single_query_and_alerts_accumulation` and browser walkthrough. Returns `threshold: 0.89`, `attack_score`, `risk_label`, and flags alerts when $\text{score} \ge 0.89$. |
| **CSV upload** | CSV validated, normalized, processed chronologically via shared pipeline. | Implemented `POST /analyze/csv` in `api/main.py`. Verified in `tests/test_e2e.py:test_e2e_csv_upload_valid_flow` and browser CSV tab. Handles missing timestamps and skips invalid rows gracefully. |
| **Behavioural history** | Related events share history within a capture; unrelated captures do not. | Partitioned behavioral extractors by `capture_id`. Verified in `tests/test_e2e.py:test_e2e_capture_isolation` ensuring events under `capture_alpha` do not contaminate `capture_beta`. |
| **Errors** | Invalid requests/rows return clear, documented errors. | Verified in `tests/test_api.py` and `tests/test_e2e.py`. Empty batches and missing FQDN headers raise HTTP 400/422 with descriptive detail strings. |
| **Alerts and statistics** | Alert list and aggregate counts match actual processed records. | Implemented `GET /alerts` and `GET /statistics` with in-memory event tracking. Verified in `tests/test_e2e.py` and live dashboard telemetry (processed 103 queries -> recorded 91 suspicious, 12 benign). |
| **Dashboard** | Charts/counts reflect live API responses, not static demo values. | Replaced static placeholder values in `LiveStatsCards.jsx`, `LiveAlertsTable.jsx`, and `TrafficTimelinePlaceholder.jsx` with dynamic API hooks. Dashboard updates automatically. |
| **Metrics labels** | Model metrics identify the model and threshold and are marked diagnostic/development. | `GET /model-performance` returns `diagnostic_label: "diagnostic/development evaluation, not independent final test"`, artifact path, and threshold 0.89. Displayed in UI callout. |
| **Verification** | Existing tests and new endpoint tests pass; setup/demo can be reproduced by another member. | All 89 backend pytest tests and 8 frontend tests pass 100%. `verify_release_models` passes bit-for-bit. Complete walkthrough documented in `docs/DEMO.md` and `Makefile`. |

---

## 8. Test Suite Verification Metrics

### Before vs. After Test Counts

| Test Suite | Baseline State (`main`) | After Param Merge | Final Integrated State (`integration/soham-e2e`) |
|---|---|---|---|
| **Backend Pytest** | 67 passed, 13 subtests | 78 passed, 13 subtests | **89 passed, 13 subtests passed (100%)** |
| **Release Model Verification** | 2 release models reproduced | 2 release models reproduced | **2 release models reproduced (100% bit-for-bit)** |
| **Frontend Tests (`npm test`)** | 0 tests (missing script) | 6 passed tests | **8 passed tests (100%)** |
| **Frontend Build (`npm run build`)** | Passed | Passed | **Passed (0 warnings, 0 errors)** |

---

## 9. Dashboard Demonstration Visual Evidence

### Initial Dashboard State (Connected to Live API)
![Initial Dashboard](screenshots/dashboard_initial.png)
*Figure 9.1: Live CyberTrace Dashboard initialized, showing real-time connectivity to FastAPI backend, active inference forms, and ready alert feed.*

### Live Telemetry & Populated Alert Feed After Ingestion
![Active Dashboard with Live Ingestion](screenshots/dashboard_active.png)
*Figure 9.2: Live CyberTrace Dashboard after processing single queries and CSV upload. Telemetry reflects 103 total processed queries (91 suspicious, 12 benign), alert feed populated with individual alert IDs and trigger indicators, and traffic breakdown chart active.*

---

## 10. Summary of Key Limitations & Operational Scope

1. **Diagnostic Evaluation Context:**
   The reported metrics (Random Forest F1 = 95.03%, Accuracy = 99.60%, FPR = 0.00% on 45,240 records) represent development evaluations on outer fold 5. They do not constitute an untouched independent test on production enterprise traffic.
2. **Synthetic Attack Reliance:**
   Attacks were simulated using known exfiltration tools and pacing. Zero observed false positives applies strictly to the 43,340 evaluated benign records.
3. **Encrypted DNS:**
   CyberTrace analyzes plaintext DNS queries where domain names are transparent. DoH/DoT tunneling requires TLS termination, host telemetry, or proxy inspection.
4. **In-Memory Retention:**
   Active alerts and cumulative traffic metrics reside in an in-memory ring buffer (up to 500 events) designed for local demonstration speed; production deployments would connect to a persistent time-series datastore.
