# Post-Hoc Review: PR #4 (FastAPI Inference & Initial Batch Analysis)

**PR:** #4 (`feature/independent-batch-analysis` -> `main`)  
**Author:** Pranay Vora (`vorapranay1412`)  
**Reviewer:** Soham (Project Coordination & Integration)  
**Date:** 2026-10-13  
**Status:** Merged  

---

## 1. Scope & Deliverable Overview
PR #4 introduced the initial FastAPI web service in `api/main.py`:
- REST endpoints: `GET /`, `GET /health`, `POST /predict`, `POST /analyze`
- Model lifecycle management: Loaded model bundle via lifespan context manager.

## 2. Technical Strengths
- **Single Model Load on Startup:** Correctly leveraged FastAPI's async `lifespan` context manager (`api/main.py:36-48`) to load `random_forest.joblib` once at startup, rather than per request.
- **Strict Canonical Pipeline Utilization:** Called `load_model()` and `predict_features()` from `src.ml.artifact` rather than directly calling `bundle["model"].predict()`, thereby properly applying the 0.89 decision threshold.

## 3. Concrete Issues & Code References (Verified)
1. **Recreation of Behavioral Extractor Per Query Inside `/analyze` (Bug Confirmed):**
   - In `api/main.py:144-147` of PR #4:
     ```python
     for query in batch.queries:
         ...
         # Fresh behavioral context for this query.
         behavioral_extractor = BehavioralFeatureExtractor(window_seconds=60.0)
         behavioral_features = behavioral_extractor.extract(record)
         features.update(behavioral_features)
     ```
     By creating a fresh `BehavioralFeatureExtractor` on every single iteration of the query loop, query history was destroyed immediately. Every single query was treated as the first query (`time_interval = -1.0`, `query_frequency = 1.0`, `unique_subdomains = 1.0`), completely disabling the sliding-window behavioral features for batch traffic.
2. **Missing CORS Middleware & Zero API Tests (Confirmed):**
   - PR #4 contained zero CORS headers or middleware. When the Vite frontend on port 3000 attempted cross-origin requests, browser security policies blocked them.
   - PR #4 was merged with zero backend automated tests (`tests/test_api.py` did not exist in PR #4).
3. **Missing Assigned Endpoints (Confirmed):**
   - Out of the 5 endpoints required by the handoff specification (Section 4), PR #4 only implemented 2 (`/predict` and `/analyze`). It omitted:
     - `GET /alerts`: To retrieve detected suspicious queries.
     - `GET /statistics`: To summarize traffic counts and detection rates.
     - `GET /model-performance`: To serve offline diagnostic metrics.
4. **No Chronological Handling:**
   - In PR #4, queries were passed directly to feature extraction in whatever order they arrived in the payload, without chronological sorting by timestamp or epoch.

## 4. Downstream Integration Impact & Resolution
- Param's branch `fix/backend-frontend-remediation` patched the behavioral extractor loop in `/analyze` and added CORS.
- In `integration/soham-e2e`, I implement the remaining 3 endpoints (`/alerts`, `/statistics`, `/model-performance`), add multipart `POST /analyze/csv`, formalize the schemas in `docs/CONTRACTS.md`, and verify with `tests/test_contracts.py` and `tests/test_e2e.py`.
