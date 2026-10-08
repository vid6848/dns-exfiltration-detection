# Random Forest v0.1 experiment results

## Outcome

The repeatable training workflow is complete. The saved model fails the held-out
benign-domain test at its validation-selected operating threshold. Treat this
artifact as an experimental benchmark, not a deployment-ready detector. No split,
hyperparameter or threshold was changed in response to the held-out test scores.

## Selected model

- 150 trees; maximum depth 12; minimum leaf size 1.
- `class_weight="balanced_subsample"`; `max_features="sqrt"`; random seed 42.
- Selected attack probability threshold: **0.3**.
- Training uses two workers; inference uses one worker for deterministic sums.
- Estimator fitted on training records only; no validation or test refit.
- Feature order: see `feature_order.json`.

## Domain-disjoint split

| Split | Rows | Benign | Attack | Apex domains |
|---|---:|---:|---:|---:|
| train | 54,038 | 47,838 | 6,200 | 1,161 |
| validation | 17,796 | 15,896 | 1,900 | 378 |
| test | 38,155 | 36,255 | 1,900 | 3 |

All rows for each apex domain, across every source IP, belong to one split.
Five stratified group folds target 60/20/20, but large intact domains make actual
row proportions approximately 49.1% / 16.2% / 34.7%. The test set has only three
apex domains: benign `amazonaws.com`, and attack domains `cloud-telemetry.io` and
`srv-heartbeat.co`. This is a narrow domain stress test, not broad evidence of
real-world performance. Source hosts may overlap; this is not an unseen-host or
future-time holdout. Behavioral features are independently recomputed in each
partition using the shared causal APIs.

## Held-out comparison

Both models are selected on the same training/validation partitions and evaluated
on the same final test records. The original row-split baseline scores are not
directly comparable to these results.

| Measure | Random Forest | Retuned statistical baseline |
|---|---:|---:|
| Accuracy | 0.053414 | 0.044241 |
| Precision | 0.049978 | 0.043188 |
| Recall | 1.000000 | 0.860000 |
| F1 | 0.095198 | 0.082245 |
| False-positive rate | 0.996194 | 0.998511 |
| TP | 1,900 | 1,634 |
| TN | 138 | 54 |
| FP | 36,117 | 36,201 |
| FN | 0 | 266 |

Validation RF F1 was 1.000000, with no false positives.
On test, it flags 36,117 of 36,255 benign queries (99.62%). This exposes a severe
distribution shift and operating-threshold generalization failure. Its test
ROC AUC is 0.997621 and average precision is 0.981944;
good ranking metrics do not repair the saved threshold's poor classification.
The test set must not be reused to select a more favorable threshold.

## Reproducibility and validation

- Two independent full-data runs produced identical serialized model checksums,
  split manifests, feature contracts, predictions, validation trials and final metrics.
- All 53 tests passed (plus 13 subtests).
- Model reload produces identical attack probabilities.
- Input, code and model SHA-256 checksums and exact dependency versions are logged.
- `verification.json` records the checks; `experiment.json` contains complete
  selection trials, baseline thresholds, importance values and limitations.

## Follow-up experiment

Before deployment, collect additional legitimate high-entropy/cloud traffic and
independent attack captures. Predeclare a new validation/test protocol with more
benign domain groups, and tune the operating threshold on validation data. Keep
this holdout result as evidence rather than selecting improvements against it.
