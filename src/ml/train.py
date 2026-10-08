"""Repeatable RF selection. Test data is evaluated only after selection freezes."""

import argparse
import csv
import hashlib
import importlib.metadata
import itertools
import json
import platform
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from src.baseline.detector import BaselineExample, BASELINE_FEATURE_NAMES, select_thresholds
from .artifact import load_model, predict_features
from .data import derive_features, load_records, split_records
from .features import FEATURE_ORDER


def classification_metrics(labels, predictions, probabilities=None):
    tn, fp, fn, tp = (int(n) for n in confusion_matrix(labels, predictions, labels=[0, 1]).ravel())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    result = {
        "accuracy": (tp + tn) / len(labels), "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }
    if probabilities is not None:
        result.update(roc_auc=float(roc_auc_score(labels, probabilities)),
                      average_precision=float(average_precision_score(labels, probabilities)))
    return result


def select_forest(x_train, y_train, x_validation, y_validation, seed=42, n_jobs=1):
    """No test argument: select by validation F1, then lower FPR, then recall.

    Grid and tie-breaking are fixed in advance; threshold is selected alongside
    tree parameters. The saved model remains fitted on training data only.
    """
    best, best_key, trials = None, None, []
    for candidate_id, (depth, leaf, weight) in enumerate(
        itertools.product((12, None), (1, 5), (None, "balanced_subsample")), start=1
    ):
        params = dict(n_estimators=150, max_depth=depth, min_samples_leaf=leaf,
                      class_weight=weight, max_features="sqrt", random_state=seed, n_jobs=n_jobs)
        model = RandomForestClassifier(**params).fit(x_train, y_train)
        # Parallel fitting is allowed; serialize probability summation order so
        # inference and artifact reloads produce bit-for-bit repeatable results.
        model.n_jobs = 1
        probabilities = model.predict_proba(x_validation)[:, 1]
        for threshold in (0.3, 0.5, 0.7):
            metrics = classification_metrics(y_validation, probabilities >= threshold, probabilities)
            trials.append(dict(candidate_id=candidate_id, parameters=params,
                               decision_threshold=threshold, validation=metrics))
            key = (metrics["f1"], -metrics["false_positive_rate"], metrics["recall"], metrics["precision"])
            if best_key is None or key > best_key:
                best_key = key
                best = dict(model=model, decision_threshold=threshold, parameters=params,
                            validation=metrics, candidate_id=candidate_id)
        print(f"Trained RF candidate {candidate_id}/8", flush=True)
    return best, trials


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def baseline_examples(rows, labels):
    return [BaselineExample({name: row[name] for name in BASELINE_FEATURE_NAMES}, int(label))
            for row, label in zip(rows, labels)]


def run_training(input_path, output_dir, seed=42, window_seconds=60.0, n_jobs=1):
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("Output directory must be empty; use a new path to preserve experiment results")
    records, removed = load_records(input_path)
    partitions = split_records(records, seed)
    print("Split rows: " + str({k: len(v) for k, v in partitions.items()}), flush=True)
    # Independent history in each partition; input's cached features are ignored.
    derived = {name: derive_features(items, window_seconds) for name, items in partitions.items()}
    train_rows, x_train, y_train = derived["train"]
    validation_rows, x_validation, y_validation = derived["validation"]
    test_rows, x_test, y_test = derived["test"]
    selected, trials = select_forest(x_train, y_train, x_validation, y_validation, seed, n_jobs)
    baseline, baseline_validation = select_thresholds(
        baseline_examples(train_rows, y_train), baseline_examples(validation_rows, y_validation))
    # Selection is now frozen for BOTH methods. Never optimize against test.
    bundle = dict(schema_version=1, model=selected["model"], feature_order=list(FEATURE_ORDER),
                  decision_threshold=selected["decision_threshold"], window_seconds=window_seconds,
                  first_query_time_interval=-1.0, classes=[0, 1], seed=seed,
                  input_sha256=sha256_file(input_path),
                  inference_n_jobs=1,
                  sklearn_version=importlib.metadata.version("scikit-learn"))
    artifact_path = output_dir / "random_forest.joblib"
    joblib.dump(bundle, artifact_path, compress=3)
    reloaded = load_model(artifact_path)
    predictions, probabilities = predict_features(reloaded, test_rows)
    original_probabilities = selected["model"].predict_proba(x_test)[:, 1]
    if not np.array_equal(probabilities, original_probabilities):
        raise AssertionError("Artifact reload changed predictions")
    test_metrics = classification_metrics(y_test, predictions, probabilities)
    split_summary = {}
    for name, items in partitions.items():
        split_summary[name] = dict(rows=len(items),
            benign=sum(e.record.label == 0 for e in items), attack=sum(e.record.label == 1 for e in items),
            apex_domains=len({e.record.apex_domain for e in items}),
            attack_apex_domains=sorted({e.record.apex_domain for e in items if e.record.label == 1}),
            earliest_epoch=min(e.record.epoch_time for e in items),
            latest_epoch=max(e.record.epoch_time for e in items))
    with (output_dir / "split_manifest.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["input_row_id", "split", "apex_domain"])
        for name, items in partitions.items():
            writer.writerows((e.row_id, name, e.record.apex_domain) for e in items)
    with (output_dir / "test_predictions.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["input_row_id", "label", "prediction", "attack_probability"])
        writer.writerows((e.row_id, int(y), int(p), float(prob))
                         for e, y, p, prob in zip(partitions["test"], y_test, predictions, probabilities))
    source_hashes = {str(path.as_posix()): sha256_file(path)
                     for root in ("src/ml", "src/features", "src/preprocessing", "src/baseline")
                     for path in sorted(Path(root).glob("*.py"))}
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    log = dict(schema_version=1, created_at_utc=datetime.now(timezone.utc).isoformat(), seed=seed,
        input=dict(path=input_path.as_posix(), sha256=bundle["input_sha256"], rows_read=len(records)+len(removed),
                   rows_used=len(records), duplicate_rows_removed=removed),
        environment=dict(python=platform.python_version(), platform=platform.platform(),
            packages={name: importlib.metadata.version(name) for name in
                      ("scikit-learn", "numpy", "scipy", "joblib", "threadpoolctl", "narwhals", "cloudpickle")}),
        source=dict(git_head_at_run=commit, file_sha256=source_hashes),
        feature_order=list(FEATURE_ORDER), behavioral_window_seconds=window_seconds,
        split=dict(method="StratifiedGroupKFold(5), apex_domain across all clients; test fold 0, validation fold 1",
                   requested_ratios=dict(train=0.6, validation=0.2, test=0.2),
                   summary=split_summary, group_overlap=0, independently_recomputed_features=True),
        selection=dict(objective="validation F1; ties: lower FPR, higher recall, higher precision, first candidate",
                       refit_on_validation=False, candidate_count=8, threshold_candidates=[0.3, 0.5, 0.7], trials=trials),
        random_forest=dict(parameters=selected["parameters"], decision_threshold=selected["decision_threshold"],
            selected_candidate_id=selected["candidate_id"], validation=selected["validation"], test=test_metrics,
            feature_importances=dict(zip(FEATURE_ORDER, map(float, selected["model"].feature_importances_)))),
        baseline=dict(thresholds=asdict(baseline.config), validation=asdict(baseline_validation),
            test=classification_metrics(y_test, [baseline.predict(e.features) for e in baseline_examples(test_rows, y_test)])),
        artifacts=dict(model_sha256=sha256_file(artifact_path), roundtrip_predictions_identical=True),
        limitations=["Synthetic attacks, one capture environment, only ten attack apex domains.",
            "Domain-disjoint evaluation is not a future-time or unseen-host holdout.",
            "Apex grouping inherits the preprocessing module's fixed suffix list.",
            "Groups can have shared generator profiles across domains; unknown campaign IDs cannot be isolated.",
            "Class balance and row ratios are approximate because domains remain intact.",
            "Original reported baseline used random row splits and is not directly comparable."])
    write_json(output_dir / "experiment.json", log)
    write_json(output_dir / "feature_order.json", dict(feature_order=list(FEATURE_ORDER),
               decision_threshold=selected["decision_threshold"], window_seconds=window_seconds,
               first_query_time_interval=-1.0, classes=[0, 1]))
    print("RF held-out test: " + json.dumps(test_metrics), flush=True)
    print("Baseline held-out test: " + json.dumps(log["baseline"]["test"]), flush=True)
    print(f"Saved model, feature order, split manifest, predictions and experiment log to {output_dir}")
    return log


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/processed/cleaned_unified_v0.1.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/random_forest_v0.1"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--n-jobs", type=int, default=1)
    args = parser.parse_args()
    run_training(args.input, args.output_dir, args.seed, args.window_seconds, args.n_jobs)


if __name__ == "__main__":
    main()
