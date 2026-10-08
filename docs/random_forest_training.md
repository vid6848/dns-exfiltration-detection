# Random Forest training and inference handoff

This stage trains a Random Forest using the ten derived DNS features and compares
it with the statistical baseline on the same domain-disjoint partitions. Run
commands from the repository root. The committed experiment uses Python 3.12
and exact dependency versions in `requirements-training.txt`.

## Reproduce training

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m src.ml.train --seed 42 --n-jobs 2 --output-dir artifacts/random_forest_repeat
```

On Linux/macOS use `.venv/bin/python` instead. Training defaults to
`data/processed/cleaned_unified_v0.1.csv`, a 60-second window, seed 42, and one
worker. The committed experiment uses two workers for fitting. Probability
prediction uses one worker for deterministic floating-point summation. Existing
output directories must be empty: a new run cannot silently overwrite the
published experiment.
Input CSVs need labels and the raw fields accepted by preprocessing. Cached
derived feature columns are ignored and recomputed using the shared modules.

## Split and leakage controls

- Deduplicate normalized DNS events before allocation; reject conflicting labels
  and malformed rows. Labels must be exactly 0 or 1.
- Group by **apex domain across all clients**, which is stricter than grouping
  by `(src_ip, apex_domain)`. All queries for a given apex stay in one partition,
  so repeated domain patterns and each client/domain history cannot cross splits.
- Use seeded five-fold `StratifiedGroupKFold`: fold 0 is the final test set,
  fold 1 validation, and the remaining three training. Target ratios are 60/20/20;
  actual row ratios and class balance can differ because large domains stay intact.
  Split allocation uses labels to balance classes, never prediction performance.
- Require at least five domains per class and both classes in each partition.
  Fail if the data cannot support this protocol; never fall back to random rows.
- Chronologically order each split and instantiate a fresh behavioral extractor.
  Each query sees only earlier queries and itself in its own client/domain group.
- Only the ten columns below enter the estimator. IP addresses, domain names,
  provenance, absolute timestamps, epoch values, and labels never enter `X`.

This is an **unseen-domain** experiment. Timestamps may overlap across partitions;
it does not measure future-time or unseen-host generalization. Domain isolation
does not separate unknown campaigns that reuse generator profiles across domains.
The parser's fixed suffix list also limits apex identification. Synthetic attacks
and the small pool of ten attack domains limit real-world conclusions.

## Feature order and semantics

```python
["query_length", "longest_label_length", "number_of_labels", "entropy",
 "digit_ratio", "special_char_ratio", "subdomain_length", "query_frequency",
 "unique_subdomains", "time_interval"]
```

The first seven come directly from `src.features.per_query`. Entropy is calculated
over the whole normalized query; dots count toward `special_char_ratio`.
The final three come from `src.features.behavioral`: counts include the current
query within the inclusive 60-second window, and the first interval is `-1.0`.
Later intervals refer to the previous group query even if it has left the window.
`query_frequency` is a count, not queries per second. No scaling is applied.

## Model selection

Eight fixed configurations use 150 trees, `max_features="sqrt"`, depths of 12
or unlimited, leaf sizes of 1 or 5, and class weights of none or
`balanced_subsample`. Each is fitted on training data only. Validation selects
the model and decision threshold from 0.3, 0.5, and 0.7 by highest F1, then lower
false-positive rate, higher recall, higher precision, then first grid entry.

The selected estimator is **not refitted on validation**. This preserves the
model/threshold combination actually selected. Both RF and baseline selection
freeze before their final test evaluation. Baseline candidates use training
data and are selected on this same validation split using the existing API.
The previously reported baseline numbers used random row splits and should
not be compared directly with this experiment's domain-disjoint RF results.

## Deliverables and inference

The committed experiment's results and interpretation are in
[`../artifacts/random_forest_v0.1/RESULTS.md`](../artifacts/random_forest_v0.1/RESULTS.md).
That holdout exposes a severe false-positive problem; the artifact is an
experimental benchmark, not a deployment-ready detector.

`artifacts/random_forest_v0.1/` contains:

- `random_forest.joblib`: trained estimator, order, threshold, class mapping,
  window size, input hash, and sklearn version.
- `feature_order.json`: readable inference contract and chosen threshold.
- `experiment.json`: all 24 validation trials, selected settings, both final
  evaluations, class counts, attack domain allocation, dependency versions,
  code/data/model hashes, feature importance, and limitations.
- `split_manifest.csv`: original input data-row number, split, and apex domain.
- `test_predictions.csv`: original row number, truth, prediction, and probability.

```python
from pathlib import Path
from src.ml.artifact import load_model, predict_features

bundle = load_model(Path("artifacts/random_forest_v0.1/random_forest.joblib"))
# feature_rows are mappings with the ten correctly calculated numeric features.
predictions, attack_probabilities = predict_features(bundle, feature_rows)
```

Use `predict_features`, rather than calling `model.predict()` directly: the saved
decision threshold can differ from 0.5. Reuse the same normalization and streaming
behavioral APIs at inference. Reusing IPs as grouping anchors is allowed; feeding
them to the forest is not. Load only trusted joblib files. Scikit-learn artifact
compatibility requires the recorded package versions.

With the same input, code, pinned environment and seed, split assignments,
selected settings and predictions should repeat. Timestamps and absolute file
paths in the experiment log naturally differ across runs.
