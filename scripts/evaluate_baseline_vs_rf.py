
"""Compare the frozen statistical baseline and latest RF on identical records.

This is a diagnostic development evaluation, not an independent final test.
Existing model and experiment artifacts are read-only.
"""

import csv
import json
from pathlib import Path

import numpy as np

from src.baseline.detector import (
    BASELINE_FEATURE_NAMES,
    BaselineDetector,
    ThresholdConfig,
)
from src.ml.artifact import load_model, predict_features
from src.ml.data import derive_features, load_records
from src.ml.train import classification_metrics, sha256_file


SOURCE_CSV = Path("data/processed/cleaned_unified_v0.1.csv")
EXPERIMENT_DIR = Path("artifacts/aws_benign_expansion_v0.1")
MODEL_PATH = EXPERIMENT_DIR / "random_forest.joblib"
EXPERIMENT_PATH = EXPERIMENT_DIR / "experiment.json"
SAVED_PREDICTIONS_PATH = EXPERIMENT_DIR / "diagnostic_predictions.csv"

OUTPUT_DIR = Path("evaluation/results/baseline_vs_rf_v1")

# Frozen rule from the engineering handoff. Do not tune on evaluation data.
BASELINE_CONFIG = ThresholdConfig(
    query_length=52.0,
    entropy=4.309101,
    query_frequency=41.0,
    unique_subdomains=41.0,
    min_indicators=2,
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def main() -> None:
    # --------------------------------------------------------------
    # 1. Validate input files and preserve existing output artifacts.
    # --------------------------------------------------------------
    required_paths = (
        SOURCE_CSV,
        MODEL_PATH,
        EXPERIMENT_PATH,
        SAVED_PREDICTIONS_PATH,
    )

    for path in required_paths:
        if not path.is_file():
            raise FileNotFoundError(f"Required file is missing: {path}")

    if OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        raise FileExistsError(
            f"Output directory is not empty: {OUTPUT_DIR}. "
            "Choose a new output directory to preserve previous results."
        )

    experiment = json.loads(EXPERIMENT_PATH.read_text(encoding="utf-8"))

    # Check that we are using the exact source dataset recorded by the
    # experiment, rather than a similarly named or modified CSV.
    actual_input_hash = sha256_file(SOURCE_CSV)
    expected_input_hash = experiment["input_sha256"]

    if actual_input_hash != expected_input_hash:
        raise AssertionError(
            "The source CSV hash differs from the experiment metadata. "
            "Do not continue with a potentially mismatched dataset."
        )

    # --------------------------------------------------------------
    # 2. Load the saved model and reconstruct the canonical features.
    # --------------------------------------------------------------
    bundle = load_model(MODEL_PATH)
    window_seconds = float(bundle["window_seconds"])

    records, duplicate_rows_removed = load_records(SOURCE_CSV)

    # Behavioral features must be derived in chronological, causal order.
    records.sort(key=lambda example: (example.record.epoch_time, example.row_id))

    feature_rows, _, derived_labels = derive_features(
        records,
        window_seconds=window_seconds,
    )

    if len(records) != len(feature_rows):
        raise AssertionError("The feature count does not match the record count.")

    if len(records) != len(derived_labels):
        raise AssertionError("The derived label count does not match the records.")

    # row_id is the original one-based CSV data-row number. Keep the
    # record and its freshly derived feature dictionary together.
    lookup = {
        example.row_id: (example, features, int(label))
        for example, features, label in zip(records, feature_rows, derived_labels)
    }

    # --------------------------------------------------------------
    # 3. Load the exact saved diagnostic evaluation population.
    # --------------------------------------------------------------
    saved_rows = read_csv(SAVED_PREDICTIONS_PATH)
    saved_ids = [int(row["input_row_id"]) for row in saved_rows]
    saved_id_set = set(saved_ids)

    if len(saved_ids) != len(saved_id_set):
        raise AssertionError("Duplicate input_row_id values in diagnostic CSV.")

    expected_count = int(experiment["evaluation_rows"])

    if len(saved_rows) != expected_count:
        raise AssertionError(
            f"Expected {expected_count} diagnostic rows, found {len(saved_rows)}."
        )

    missing_ids = saved_id_set - set(lookup)
    if missing_ids:
        sample = sorted(missing_ids)[:10]
        raise AssertionError(f"Diagnostic row IDs missing from source: {sample}")

    # Preserve the saved diagnostic CSV ordering for inference and comparison.
    selected = [lookup[row_id] for row_id in saved_ids]
    selected_records = [item[0] for item in selected]
    selected_features = [item[1] for item in selected]
    labels = np.asarray(
        [int(row["label"]) for row in saved_rows],
        dtype=np.int64,
    )

    # Confirm that each saved label and apex matches the canonical record.
    source_labels = np.asarray(
        [example.record.label for example in selected_records],
        dtype=np.int64,
    )

    if not np.array_equal(labels, source_labels):
        raise AssertionError("Saved diagnostic labels do not match the source.")

    for saved, example in zip(saved_rows, selected_records):
        if saved["apex_domain"] != example.record.apex_domain:
            raise AssertionError(
                f"Apex-domain mismatch at row ID {example.row_id}."
            )

    # Require complete apex histories; do not evaluate only fragments
    # of a domain's chronological records.
    evaluation_apexes = {
        example.record.apex_domain for example in selected_records
    }
    expected_domain_ids = {
        example.row_id
        for example in records
        if example.record.apex_domain in evaluation_apexes
    }

    if expected_domain_ids != saved_id_set:
        raise AssertionError(
            "The diagnostic records do not contain complete apex histories."
        )

    # --------------------------------------------------------------
    # 4. Reproduce the latest RF predictions with its saved threshold.
    # --------------------------------------------------------------
    rf_predictions, attack_scores = predict_features(bundle, selected_features)

    saved_rf_predictions = np.asarray(
        [int(row["prediction"]) for row in saved_rows],
        dtype=np.int64,
    )
    saved_scores = np.asarray(
        [float(row["attack_probability"]) for row in saved_rows],
        dtype=float,
    )

    if not np.array_equal(rf_predictions, saved_rf_predictions):
        raise AssertionError("Fresh RF predictions do not match saved predictions.")

    if not np.array_equal(attack_scores, saved_scores):
        raise AssertionError("Fresh RF scores do not match saved scores.")

    saved_metrics = experiment["augmented"]["pooled"]
    rf_metrics = classification_metrics(labels, rf_predictions, attack_scores)

    if rf_metrics != saved_metrics:
        raise AssertionError(
            "Recomputed RF metrics differ from the experiment's recorded metrics."
        )

    # --------------------------------------------------------------
    # 5. Run the actual rule-based statistical baseline.
    # --------------------------------------------------------------
    baseline_detector = BaselineDetector(BASELINE_CONFIG)

    baseline_predictions = np.asarray(
        [
            baseline_detector.predict(
                {
                    name: float(features[name])
                    for name in BASELINE_FEATURE_NAMES
                }
            )
            for features in selected_features
        ],
        dtype=np.int64,
    )

    baseline_metrics = classification_metrics(labels, baseline_predictions)

    # --------------------------------------------------------------
    # 6. Save results separately from Jaynish's experiment artifacts.
    # --------------------------------------------------------------
    report = {
        "evaluation_records": len(saved_rows),
        "source_csv": str(SOURCE_CSV),
        "source_sha256": actual_input_hash,
        "model_artifact": str(MODEL_PATH),
        "decision_threshold": float(bundle["decision_threshold"]),
        "behavioral_window_seconds": window_seconds,
        "duplicate_source_rows_removed": len(duplicate_rows_removed),
        "baseline_rule": {
            **BASELINE_CONFIG.as_dict(),
            "min_indicators": BASELINE_CONFIG.min_indicators,
            "selection": "Frozen from engineering handoff; not tuned on evaluation data",
        },
        "statistical_baseline": baseline_metrics,
        "random_forest": rf_metrics,
        "verification": {
            "source_hash_matches": True,
            "unique_diagnostic_row_ids": True,
            "source_labels_match": True,
            "apex_domains_match": True,
            "complete_apex_histories": True,
            "rf_predictions_reproduced": True,
            "rf_probabilities_reproduced": True,
            "rf_metrics_match_experiment": True,
        },
        "scope": (
            "Previously inspected diagnostic development evaluation. "
            "Not an independent final test or proof of real-world generalization."
        ),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    metrics_path = OUTPUT_DIR / "baseline_vs_rf_metrics.json"
    predictions_path = OUTPUT_DIR / "baseline_vs_rf_predictions.csv"

    metrics_path.write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    with predictions_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "input_row_id",
                "apex_domain",
                "label",
                "statistical_baseline_prediction",
                "random_forest_prediction",
                "random_forest_attack_probability",
            ]
        )

        writer.writerows(
            (
                saved["input_row_id"],
                saved["apex_domain"],
                int(label),
                int(baseline_prediction),
                int(rf_prediction),
                float(score),
            )
            for saved, label, baseline_prediction, rf_prediction, score in zip(
                saved_rows,
                labels,
                baseline_predictions,
                rf_predictions,
                attack_scores,
            )
        )

    print("Evaluation completed successfully.")
    print(f"Records evaluated: {len(saved_rows):,}")
    print(f"RF decision threshold: {bundle['decision_threshold']}")
    print("\nStatistical baseline:")
    print(json.dumps(baseline_metrics, indent=2))
    print("\nLatest Random Forest:")
    print(json.dumps(rf_metrics, indent=2))
    print(f"\nMetrics saved to: {metrics_path}")
    print(f"Predictions saved to: {predictions_path}")


if __name__ == "__main__":
    main()
