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
   - In `scripts/evaluate_baseline_vs_rf.py` and the evaluation report, Harshul noted that `source_hashes_match = false` was observed during script execution, but left the root cause uninvestigated ("cause remains unresolved").
2. **Missing Direct REST Integration Endpoint:**
   - The metrics generated in `evaluation/results/baseline_vs_rf_v1/baseline_vs_rf_metrics.json` were left on disk as static JSON, without a corresponding backend API endpoint (`GET /model-performance`) to serve them dynamically to the frontend dashboard.
3. **Hardware Latency Caveat:**
   - Latency benchmarks were run locally on a Windows development laptop using only 5 measured repetitions for p95 latency, which introduces platform-specific variance.

## 4. Downstream Integration Impact & Resolution
- In `integration/soham-e2e`, I resolved the mystery behind `source_hashes_match = false` (Windows CRLF vs Linux/macOS LF git checkout discrepancy, documented in `docs/provenance_investigation.md`).
- Built the `GET /model-performance` endpoint in the API to expose these verified evaluation metrics, and updated the React frontend (`OfflineModelPerformance.jsx`) to consume it directly.
