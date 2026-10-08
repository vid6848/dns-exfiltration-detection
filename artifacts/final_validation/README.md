# Final training validation and handoff

Fresh verification run for the requested main-branch merge, 2026-10-08.

## Verification results

- Complete pytest suite: **67 passed, 13 subtests passed**.
- Dependency integrity: `pip check` passed, with no broken requirements.
- Python compilation: all `src` and `scripts` modules passed.
- Git whitespace/diff checks passed.
- v0.2 nested experiment verification: all eight checks passed.
- AWS expansion experiment verification: all seventeen checks passed.
- Public training-subset restoration: checksum matched the recorded canonical CSV.
- Fresh raw-event inference replay: all **38,155** v0.1 evaluation predictions
  and all **45,240** AWS-expansion evaluation predictions matched exactly,
  including bit-for-bit attack probabilities. Metrics were recomputed and matched.

The inference replay loads the committed models, recomputes the shared features
from canonical raw events and applies the saved thresholds. It does not fit or
retune the models. See `model_replay.json` for the current evidence. The original
experiment and test data remain preserved for audit.

## Latest model results

The latest model is `artifacts/aws_benign_expansion_v0.1/random_forest.joblib`.
It uses a selected threshold of **0.89** and the exact ordered ten-feature schema.
Call `load_model` and `predict_features` from `src.ml.artifact` so inference uses
this threshold rather than the estimator's default 0.5 decision rule.

Development training: **150,353 rows**, including 85,604 newly added
publisher-labelled university benign queries. AWS and all 308 diagnostic
evaluation apexes were excluded from fitting and inner selection. Captures have
separate causal behavioral histories; IPs, domain strings and absolute time are
never forest features.

Diagnostic evaluation: **45,240 rows**, comprising 43,340 benign queries and
1,900 synthetic attack queries, including 36,255 AWS benign queries.

| Metric | Previous v0.2 outer model | Benign-expanded model |
|---|---:|---:|
| AWS false positives | 36,193 / 36,255 | **0 / 36,255** |
| AWS FPR | 99.83% | **0%** |
| All evaluation benign false positives | 36,208 / 43,340 | **0 / 43,340** |
| Synthetic attack recall | 99.74% | **90.53%** |
| Missed synthetic attacks | 5 / 1,900 | **180 / 1,900** |
| Precision | 4.97% | **100%** |
| F1 | 0.094743 | **0.950276** |

TP/TN/FP/FN: **1,720 / 43,340 / 0 / 180**. Accuracy: **99.6021%**.

The AWS false-positive shortfall is resolved on this diagnostic population,
with a material reduction in attack recall. These evaluation records were
previously inspected and are development evidence, not a fresh independent
final test. The new run verifies the software and saved results; it does not
turn old records into an untouched test. Independent benign and real attack
captures remain necessary before a deployment/generalization claim. The saved
bundle remains marked `deployment_ready=False`.

## Reproduction

Run from the repository root with the pinned project environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp .pytest-work-temp
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q src scripts
.\.venv\Scripts\python.exe -m scripts.summarize_robust_training
.\.venv\Scripts\python.exe -m scripts.summarize_aws_expansion
.\.venv\Scripts\python.exe -m scripts.verify_release_models
```

For a fresh checkout, restore the public CSV to the path recorded in the
experiment before running its summarizer:

```powershell
.\.venv\Scripts\python.exe -m scripts.restore_public_benign --output .public-data-research/university_monday.csv
```

Use a new restoration path when a local copy already exists. The exact public
subset and attribution are committed with the AWS experiment. Detailed training
commands and provenance are in [the AWS expansion handoff](../../docs/aws_benign_expansion.md).
