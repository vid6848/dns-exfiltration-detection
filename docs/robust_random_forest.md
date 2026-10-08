# Random Forest v0.2: robust domain validation

This workflow addresses the v0.1 unseen-benign failure while preserving the exact
ten-feature contract and the original model/experiment. The earlier held-out
records have been inspected and now belong to the development dataset. A fresh
independent test has not been collected.

## Run

Use the pinned training dependencies already provided in `requirements-dev.txt`.
From the repository root:

```powershell
.\.venv\Scripts\python.exe -m src.ml.robust_train --n-jobs 2 --output-dir artifacts/random_forest_v0.2
.\.venv\Scripts\python.exe -m scripts.summarize_robust_training --experiment-dir artifacts/random_forest_v0.2
```

On Linux/macOS use `.venv/bin/python`. Output directories must be empty. The
defaults are seed 42, five outer folds, three inner folds, maximum pooled
validation FPR 0.01, maximum large-domain validation FPR 0.05, and 100 benign
records as the minimum domain size for the per-domain constraint. These targets
are configurable with `--max-fpr`, `--max-domain-fpr`, and `--min-group-rows`.
Changing policy defines a new development experiment; never select a policy by
its outer-fold scores. A target validated on this dataset is not a deployment
guarantee.

## Changes from v0.1

1. **Broader domain coverage per fold.** Whole apex domains still stay together
   across all source clients. Allocation balances the number of domains per
   majority class first, then row counts. A huge AWS group cannot monopolize a
   fold's benign domain allocation. Row counts are intentionally approximate.
   Allocation uses labels/group sizes, never features or model scores.
2. **Nested validation.** Each outer fold is excluded from all model/threshold
   selection. Three inner domain folds produce out-of-fold validation scores.
   The selected settings are fitted on the outer development partition and
   evaluated once on the outer held-out partition. All five outer results are
   reported, including per-domain errors and the worst-fold FPR.
3. **Explicit false-positive policy.** A candidate must satisfy both pooled FPR
   <=1% and FPR <=5% for each sufficiently large benign validation domain.
   Small-domain errors are still reported. Among eligible candidates, maximize
   mean inner-fold recall, then lower worst large-domain FPR, lower pooled FPR,
   and finally higher threshold. No eligible candidate means failure, not a
   silently published fallback model.
4. **Conservative thresholds.** Search 0.50 through 0.99 in steps of 0.01, plus
   0.995 and 0.999. Equal validation results favor the higher threshold instead
   of the first, most aggressive threshold.
5. **Stronger regularization.** The predefined eight-candidate grid uses 150
   trees, depths 8/12, minimum leaf sizes 5/20, and class weights none or
   `balanced_subsample`, with `max_features="sqrt"`.
6. **Final development model.** A separate inner-CV selection on all current
   data determines final settings. The final estimator is then refitted on all
   development records, including existing AWS benign examples. Its threshold
   comes from cross-validated scores, not in-sample fitted predictions. Nested
   results describe the selection workflow, not an independent test of this
   final all-data-refitted estimator.

## Features and leakage controls

`FEATURE_ORDER` in `src/ml/features.py` remains authoritative and unchanged.
Neither `src_ip`, `apex_domain`, `epoch_time`, provenance nor the target enters
the forest. The shared preprocessing and feature definitions remain unchanged.

Causal features are calculated in chronological order. Because each fold keeps
whole apex groups, removing another apex cannot change any `(src_ip, apex_domain)`
history. Features can therefore be cached once without crossing a fold's history
boundaries. A regression test verifies equality with independently recomputed
fold histories. Arbitrary row-level or chronological splits must not reuse this
cache argument.

Duplicate normalization and malformed-input checks still run before allocation.
At least the requested fold count of domains in each majority class is required.
All actual folds are checked for both classes. Mixed-label domains remain intact.

## Outputs and inference

`artifacts/random_forest_v0.2/` contains the saved model, feature-order contract,
complete nested experiment log, row-level nested predictions, and final
cross-validation selection predictions. Use the existing `load_model` and
`predict_features` APIs described in `random_forest_training.md` with the v0.2
artifact path. The saved threshold must be applied; `estimator.predict()` uses
a different default decision rule.

The bundle explicitly records `deployment_ready=False` and that it was fitted
on all current development data. Final-refit probability behavior can differ
from fold-fitted estimators; independent validation remains necessary.

## Remaining data work

No additional real benign capture was added. The final model now learns from
the cloud examples already present in the dataset, and nested evaluation tests
domain holdouts across the current data. Broader benign traffic (cloud/CDN,
long and random-looking names, legitimate bursts) and independently labelled
attack captures are still needed. Keep collection provenance for auditing,
exclude it from model inputs, normalize/deduplicate new records, and pass the
combined cleaned CSV through `--input` in a new output directory.

Avoid domain allowlists as a shortcut: an allowlist would conceal the observed
failure and could also suppress real attacks. Do not relabel unknown traffic
or manufacture a favorable final holdout from the already-inspected data.
