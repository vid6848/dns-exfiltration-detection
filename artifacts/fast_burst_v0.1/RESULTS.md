# fast_burst_v0.1

Served by the API since 2026-10-22. Fixes the fast-burst blind spot of
`aws_benign_expansion_v0.1`; full method and results in
[docs/fast_burst_fix.md](../../docs/fast_burst_fix.md).

| | aws_benign_expansion_v0.1 | fast_burst_v0.1 |
|---|---|---|
| Frozen fold 5 F1 / recall / false alarms | 95.03% / 90.53% / 0 | 95.40% / 91.21% / 0 |
| Fast-burst stress recall (unseen domains, 2–50 ms) | 4.2% | 88.4% |
| Decision threshold | 0.89 | 0.90 |

Files: `random_forest.joblib` (bundle), `experiment.json` (inputs, hashes, all
selection trials, metrics), `diagnostic_predictions.csv` (frozen fold,
previous vs new), `stress_predictions.csv`, `timing_sweep.csv`.
Verified by `python -m scripts.verify_release_models`.
