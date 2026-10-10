
"""Benchmark DNS feature extraction, RF inference, and end-to-end processing.

Uses the existing source dataset and saved RF artifact.
Does not retrain the model or modify Jaynish's artifacts.
"""

import csv
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

import numpy as np
import sklearn

from src.ml.artifact import load_model, predict_features
from src.ml.data import derive_features, load_records


SOURCE_CSV = Path("data/processed/cleaned_unified_v0.1.csv")
EXPERIMENT_DIR = Path("artifacts/aws_benign_expansion_v0.1")
MODEL_PATH = EXPERIMENT_DIR / "random_forest.joblib"
MANIFEST_PATH = EXPERIMENT_DIR / "feature_order.json"
DIAGNOSTICS_PATH = EXPERIMENT_DIR / "diagnostic_predictions.csv"

OUTPUT_DIR = Path("evaluation/results/baseline_vs_rf_v1/latency")

FEATURE_EXTRACTION_REPEATS = 7
INFERENCE_REPEATS = 10
END_TO_END_REPEATS = 5
WARMUP_REPEATS = 1


def sha256_file(path: Path) -> str:
    """Calculate a file's SHA-256 without loading it all into memory."""
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def prepare_features(records, window_seconds: float):
    """Derive features in chronological order with the canonical extractor."""
    ordered_records = sorted(
        records,
        key=lambda item: (item.record.epoch_time, item.row_id),
    )

    feature_rows, _, labels = derive_features(
        ordered_records,
        window_seconds=window_seconds,
    )

    if len(feature_rows) != len(ordered_records):
        raise AssertionError("Feature count differs from record count.")

    lookup = {
        item.row_id: (item, features, int(label))
        for item, features, label in zip(
            ordered_records, feature_rows, labels
        )
    }

    return ordered_records, feature_rows, labels, lookup


def summarize_timings(
    stage: str,
    samples_seconds: list[float],
    records_per_run: int,
    batch_size: int,
    warmups: int,
) -> dict:
    """Summarize repeated measurements in explicit units."""
    milliseconds = np.asarray(samples_seconds, dtype=float) * 1000.0

    if len(milliseconds) == 0 or not np.isfinite(milliseconds).all():
        raise ValueError(f"No valid measurements for stage: {stage}")

    mean_seconds = float(np.mean(samples_seconds))

    return {
        "stage": stage,
        "batch_size_records": int(batch_size),
        "records_per_run": int(records_per_run),
        "warmup_repetitions": int(warmups),
        "measured_repetitions": len(samples_seconds),
        "median_ms": float(np.median(milliseconds)),
        "p95_ms": float(np.percentile(milliseconds, 95)),
        "mean_ms": float(np.mean(milliseconds)),
        "min_ms": float(np.min(milliseconds)),
        "max_ms": float(np.max(milliseconds)),
        "mean_ms_per_record": (
            mean_seconds * 1000.0 / records_per_run
            if records_per_run else None
        ),
        "records_per_second": (
            records_per_run / mean_seconds
            if mean_seconds > 0 and records_per_run else None
        ),
    }


def measure_repeatedly(function, repetitions: int, warmups: int = 1):
    """Warm up the operation, then time complete executions."""
    for _ in range(warmups):
        function()

    samples = []

    for _ in range(repetitions):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)

    return samples


def main() -> None:
    for path in (SOURCE_CSV, MODEL_PATH, MANIFEST_PATH, DIAGNOSTICS_PATH):
        if not path.is_file():
            raise FileNotFoundError(f"Required file not found: {path}")

    if OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        raise FileExistsError(
            f"Output directory is not empty: {OUTPUT_DIR}. "
            "Choose a new output directory to preserve previous results."
        )

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    bundle = load_model(MODEL_PATH)
    window_seconds = float(manifest["window_seconds"])

    if float(bundle["decision_threshold"]) != float(
        manifest["decision_threshold"]
    ):
        raise AssertionError("Model threshold does not match the manifest.")

    diagnostic_rows = read_csv(DIAGNOSTICS_PATH)
    diagnostic_ids = [int(row["input_row_id"]) for row in diagnostic_rows]
    saved_labels = np.asarray(
        [int(row["label"]) for row in diagnostic_rows], dtype=np.int64
    )
    saved_predictions = np.asarray(
        [int(row["prediction"]) for row in diagnostic_rows], dtype=np.int64
    )
    saved_scores = np.asarray(
        [float(row["attack_probability"]) for row in diagnostic_rows],
        dtype=float,
    )

    if len(diagnostic_ids) != len(set(diagnostic_ids)):
        raise AssertionError("Diagnostic file contains duplicate row IDs.")

    expected_rows = int(len(diagnostic_rows))

    if expected_rows == 0:
        raise ValueError("The diagnostic evaluation population is empty.")

    print("Loading and preparing benchmark input...")
    records, duplicate_rows_removed = load_records(SOURCE_CSV)
    ordered, feature_rows, labels, lookup = prepare_features(
        records, window_seconds
    )

    missing = set(diagnostic_ids) - set(lookup)

    if missing:
        raise AssertionError(
            f"Diagnostic input IDs are missing from source: {sorted(missing)[:10]}"
        )

    selected = [lookup[row_id] for row_id in diagnostic_ids]
    selected_records = [item[0] for item in selected]
    selected_features = [item[1] for item in selected]
    selected_labels = np.asarray(
        [item[2] for item in selected], dtype=np.int64
    )

    if not np.array_equal(saved_labels, selected_labels):
        raise AssertionError("Diagnostic labels do not match source records.")

    for saved, item in zip(diagnostic_rows, selected_records):
        if saved["apex_domain"] != item.record.apex_domain:
            raise AssertionError(
                f"Apex-domain mismatch at source row {item.row_id}."
            )

    # Verify RF replay before reporting any timing results.
    replay_predictions, replay_scores = predict_features(
        bundle, selected_features
    )

    if not np.array_equal(replay_predictions, saved_predictions):
        raise AssertionError("RF predictions do not match saved predictions.")

    if not np.array_equal(replay_scores, saved_scores):
        raise AssertionError("RF scores do not match saved scores.")

    total_source_records = len(ordered)
    evaluation_records = len(selected_features)

    # ----------------------------------------------------------
    # A. Feature extraction only: records are already parsed.
    # ----------------------------------------------------------
    print("Benchmarking feature extraction...")
    feature_samples = measure_repeatedly(
        lambda: derive_features(ordered, window_seconds=window_seconds),
        repetitions=FEATURE_EXTRACTION_REPEATS,
        warmups=WARMUP_REPEATS,
    )

    feature_summary = summarize_timings(
        stage="feature_extraction_in_memory",
        samples_seconds=feature_samples,
        records_per_run=total_source_records,
        batch_size=total_source_records,
        warmups=WARMUP_REPEATS,
    )

    # ----------------------------------------------------------
    # B. RF inference only: feature dictionaries are precomputed.
    # ----------------------------------------------------------
    print("Benchmarking Random Forest inference...")
    batch_sizes = sorted({
        1,
        min(256, evaluation_records),
        min(1024, evaluation_records),
        min(8192, evaluation_records),
        evaluation_records,
    })

    inference_summaries = []

    for batch_size in batch_sizes:
        features_batch = selected_features[:batch_size]
        expected_predictions = saved_predictions[:batch_size]
        expected_scores = saved_scores[:batch_size]

        # Verify this batch before measuring it.
        predictions, scores = predict_features(bundle, features_batch)

        if not np.array_equal(predictions, expected_predictions):
            raise AssertionError(
                f"RF prediction mismatch for batch size {batch_size}."
            )

        if not np.array_equal(scores, expected_scores):
            raise AssertionError(
                f"RF score mismatch for batch size {batch_size}."
            )

        inference_samples = measure_repeatedly(
            lambda: predict_features(bundle, features_batch),
            repetitions=INFERENCE_REPEATS,
            warmups=WARMUP_REPEATS,
        )

        inference_summaries.append(
            summarize_timings(
                stage="random_forest_inference",
                samples_seconds=inference_samples,
                records_per_run=batch_size,
                batch_size=batch_size,
                warmups=WARMUP_REPEATS,
            )
        )

    # ----------------------------------------------------------
    # C. End-to-end: reload, parse, extract, select, and predict.
    # ----------------------------------------------------------
    def end_to_end_run():
        current_records, _ = load_records(SOURCE_CSV)
        _, _, _, current_lookup = prepare_features(
            current_records, window_seconds
        )

        missing_ids = set(diagnostic_ids) - set(current_lookup)

        if missing_ids:
            raise AssertionError(
                "Diagnostic IDs missing during end-to-end benchmark."
            )

        current_features = [
            current_lookup[row_id][1] for row_id in diagnostic_ids
        ]

        return predict_features(bundle, current_features)

    print("Verifying and benchmarking end-to-end processing...")

    end_to_end_predictions, end_to_end_scores = end_to_end_run()

    if not np.array_equal(end_to_end_predictions, saved_predictions):
        raise AssertionError("End-to-end RF predictions do not match saved data.")

    if not np.array_equal(end_to_end_scores, saved_scores):
        raise AssertionError("End-to-end RF scores do not match saved data.")

    end_to_end_samples = measure_repeatedly(
        end_to_end_run,
        repetitions=END_TO_END_REPEATS,
        warmups=WARMUP_REPEATS,
    )

    end_to_end_summary = summarize_timings(
        stage="source_csv_to_diagnostic_predictions",
        samples_seconds=end_to_end_samples,
        records_per_run=evaluation_records,
        batch_size=evaluation_records,
        warmups=WARMUP_REPEATS,
    )

    # ----------------------------------------------------------
    # Save benchmark results separately from existing artifacts.
    # ----------------------------------------------------------
    all_summaries = [
        feature_summary,
        *inference_summaries,
        end_to_end_summary,
    ]

    hardware = {
        "platform": platform.platform(),
        "processor": platform.processor() or "Not reported by operating system",
        "logical_cpu_count": os.cpu_count(),
        "python_version": sys.version,
        "numpy_version": np.__version__,
        "scikit_learn_version": sklearn.__version__,
    }

    report = {
        "source_csv": str(SOURCE_CSV),
        "source_csv_sha256": sha256_file(SOURCE_CSV),
        "model_artifact": str(MODEL_PATH),
        "model_sha256": sha256_file(MODEL_PATH),
        "decision_threshold": float(bundle["decision_threshold"]),
        "window_seconds": window_seconds,
        "source_records_after_load": total_source_records,
        "duplicate_rows_removed": len(duplicate_rows_removed),
        "diagnostic_records": expected_rows,
        "feature_count": len(manifest["feature_order"]),
        "feature_order": manifest["feature_order"],
        "warmup_repetitions_per_stage": WARMUP_REPEATS,
        "hardware_software": hardware,
        "measurements": all_summaries,
        "verification": {
            "diagnostic_ids_unique": True,
            "labels_match_source": True,
            "apex_domains_match_source": True,
            "saved_rf_predictions_reproduced": True,
            "saved_rf_scores_reproduced": True,
            "end_to_end_predictions_reproduced": True,
            "end_to_end_scores_reproduced": True,
        },
        "limitations": [
            "Measured on this local machine and filesystem, not a production sensor.",
            "Feature extraction timing starts with already-loaded records.",
            "End-to-end timing includes local CSV loading, parsing, feature extraction, selection, and RF inference.",
            "Batch average time per record is not the same as single-query latency.",
            "The p95 estimate depends on the limited number of repeated measurements.",
            "The diagnostic dataset was previously inspected during development.",
        ],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "latency_benchmark.json"
    csv_path = OUTPUT_DIR / "latency_benchmark.csv"

    json_path.write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(all_summaries[0].keys()),
        )
        writer.writeheader()
        writer.writerows(all_summaries)

    print("\nLatency benchmark completed successfully.")
    print(f"Source records: {total_source_records:,}")
    print(f"Diagnostic records: {evaluation_records:,}")
    print(f"Warm-up repetitions per stage: {WARMUP_REPEATS}")
    print("\nTiming summary (milliseconds):")
    print(
        f"{'Stage':43s} {'Batch':>9s} {'Median':>12s} "
        f"{'P95':>12s} {'Records/s':>13s}"
    )

    for row in all_summaries:
        print(
            f"{row['stage']:43s} "
            f"{row['batch_size_records']:9,d} "
            f"{row['median_ms']:12.3f} "
            f"{row['p95_ms']:12.3f} "
            f"{row['records_per_second']:13.2f}"
        )

    print(f"\nJSON report: {json_path}")
    print(f"CSV report:  {csv_path}")


if __name__ == "__main__":
    main()
