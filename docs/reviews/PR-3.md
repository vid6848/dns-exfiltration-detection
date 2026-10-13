# Post-Hoc Review: PR #3 (Model Evaluation, Feature Importance & Latency Analysis)

**PR:** #3 (`feature/harshul-evaluation` -> `main`)  
**Author:** Harshul Shah (`Harshul2827`)  
**Reviewer:** Soham (Project Coordination & Integration)  
**Date:** 2026-10-13  
**Status:** Merged  

---

## 1. Scope & Deliverable Overview
PR #3 added empirical evaluation and benchmarking between the statistical baseline and the Random Forest model:
- Evaluation scripts: `scripts/evaluate_baseline_vs_rf.py`, `scripts/benchmark_evaluation_latency.py`, `scripts/plot_feature_importance.py`, `scripts/plot_baseline_vs_rf.py`
- Research documentation: `evaluation/evaluation_report.md`
- Results & Plots: `evaluation/results/baseline_vs_rf_v1/baseline_vs_rf_metrics.json`, confusion matrix, and ROC/PR curve plots.

## 2. Technical Strengths
- **Fair Side-by-Side Comparison:** Evaluated both the 4-indicator heuristic baseline and Random Forest on the identical 45,240 diagnostic records (43,340 benign, 1,900 attack).
- **Exact Threshold Enforcement:** Strict application of the calibrated threshold $\tau = 0.89$ achieving 0.00% FPR (0 false alarms) on the diagnostic set with 90.53% attack recall.
- **Scientific Humility and Scope Disclaimers:** Explicitly marked all reported metrics as "diagnostic development evaluation, not independent final test", avoiding unsupported claims of production generalizability.

## 3. Concrete Issues & Code References
1. **Source Hash Mismatch Uninvestigated:**
   - In `scripts/evaluate_baseline_vs_rf.py` and `evaluation/results/baseline_vs_rf_v1/evaluation_report.md`, Harshul noted that `source_hashes_match = false` was observed during script execution, but left the root cause uninvestigated ("cause remains unresolved").
2. **Hardware Latency Benchmarking Sample Size:**
   - In `scripts/benchmark_evaluation_latency.py:34`, `END_TO_END_REPEATS = 5` was configured for measuring end-to-end latency on a local Windows laptop. While adequate for internal benchmarking, small repetition samples introduce hardware-dependent variance for tail latency metrics ($p95$).
3. **Absence of Evaluation Script Unit Tests:**
   - PR #3 added evaluation and latency benchmarking CLI scripts under `scripts/`, but did not add corresponding automated unit tests under `tests/` (e.g. verifying heuristic metric parsing or baseline indicator threshold evaluation against a synthetic test fixture).

## 4. Downstream Integration Impact & Resolution
- In `integration/soham-e2e`, I resolved the underlying cause of `source_hashes_match = false` (Windows CRLF vs Linux/macOS LF git checkout discrepancy, documented in `docs/provenance_investigation.md`).
- As part of the API integration layer, I implemented `GET /model-performance` in the FastAPI backend to dynamically expose Harshul's verified evaluation metrics (`baseline_vs_rf_metrics.json`) to the frontend dashboard (`OfflineModelPerformance.jsx`), keeping data consumption live and verifiable.
