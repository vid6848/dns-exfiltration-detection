# Random Forest v0.2 development results

The original v0.1 experiment is preserved. Its already-inspected test
records are now development data. Results below are nested domain-CV
estimates of the selection workflow, not an independent final test of
the saved all-development-data-refitted model.

## Nested domain-disjoint evaluation

| Outer fold | Rows | Domains | FPR | Recall | F1 | Selected threshold |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 17,878 | 309 | 0.002488 | 0.989545 | 0.985960 | 0.78 |
| 2 | 10,854 | 309 | 0.000000 | 0.896098 | 0.945202 | 0.78 |
| 3 | 18,260 | 308 | 0.000000 | 0.982632 | 0.991240 | 0.84 |
| 4 | 17,757 | 308 | 0.000000 | 0.975385 | 0.987539 | 0.9 |
| 5 | 45,240 | 308 | 0.835441 | 0.997368 | 0.094743 | 0.56 |

Pooled outer-fold metrics:

- accuracy: 0.667521
- precision: 0.210735
- recall: 0.967800
- f1: 0.346106
- false_positive_rate: 0.362510
- TP/TN/FP/FN: 9678 / 63742 / 36247 / 322

## AWS benign-domain diagnostic

All 36,255 AWS benign records were scored by an outer model
whose training and inner selection excluded the entire AWS apex domain.
False positives: 36,193; FPR: 0.998290.
The original v0.1 AWS FPR was 0.996194. The training population and
selection protocol differ here, and development choices were informed
by inspecting v0.1; this comparison is diagnostic, not a fresh test claim.

## Final saved model

- Decision threshold: 0.83.
- Parameters: `{"class_weight": "balanced_subsample", "max_depth": 12, "max_features": "sqrt", "min_samples_leaf": 5, "n_estimators": 150, "n_jobs": 2, "random_state": 42}`.
- Final selection pooled validation FPR: 0.005971.
- Worst large-domain validation FPR: 0.015612.
- Refit on all current development records, including existing AWS benign data.
- Exact ten-feature order and shared feature semantics retained.
- No independent final test available; artifact marked deployment_ready=False.

## Verification and limits

Checks passed for input/source/model hashes, feature order, complete
row coverage, domain separation, validation policy, and artifact reload.
See verification.json for checks and experiment.json for every selection trial.
No new real benign captures or independent attack recordings were added.
Unseen cloud/CDN families, parser grouping limits, and the small synthetic
attack-domain pool remain relevant limitations. Collect fresh independent
traffic before making final generalization or deployment claims.
