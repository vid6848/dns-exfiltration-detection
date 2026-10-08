"""Nested domain CV for development evaluation and conservative RF selection.

The old test set has already been inspected. All current records are therefore
development data. Outer folds score frozen inner-selected models; a separate
CV selection on all development data chooses the final all-data-refitted bundle.
No fresh independent test result is claimed for that final bundle.
"""

import argparse
import csv
import importlib.metadata
import itertools
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from .artifact import load_model, predict_features
from .data import derive_features, load_records
from .features import FEATURE_ORDER
from .group_cv import domain_folds
from .train import classification_metrics, sha256_file, write_json


THRESHOLDS = tuple(round(float(t), 3) for t in np.arange(0.50, 1.0, 0.01)) + (0.995, 0.999)


def group_metrics(labels, predictions, groups):
    """Per-domain errors, including small domains excluded from policy checks."""
    labels, predictions, groups = np.asarray(labels), np.asarray(predictions), np.asarray(groups)
    names, inverse = np.unique(groups, return_inverse=True)
    counts = lambda weights: np.bincount(inverse, weights=weights, minlength=len(names)).astype(int)
    benign_counts, attack_counts = counts(labels == 0), counts(labels == 1)
    fp_counts, fn_counts = counts((labels == 0) & (predictions == 1)), counts((labels == 1) & (predictions == 0))
    result = []
    for i, group in enumerate(names):
        benign, attacks, fp, fn = map(int, (benign_counts[i], attack_counts[i], fp_counts[i], fn_counts[i]))
        result.append(dict(apex_domain=str(group), rows=benign+attacks, benign=benign,
            attack=attacks, false_positives=fp, false_negatives=fn,
            false_positive_rate=fp / benign if benign else None,
            recall=1 - fn / attacks if attacks else None))
    return result


def validation_summary(labels, probabilities, groups, folds, threshold, min_group_rows=100, group_encoding=None):
    predictions = (probabilities >= threshold).astype(int)
    pooled = classification_metrics(labels, predictions)
    fold_scores = [classification_metrics(labels[i], predictions[i]) for i in folds]
    if group_encoding is None:
        _, inverse = np.unique(groups, return_inverse=True)
        benign_counts = np.bincount(inverse, weights=labels == 0)
    else:
        inverse, benign_counts = group_encoding
    false_positives = np.bincount(inverse, weights=(labels == 0) & (predictions == 1), minlength=len(benign_counts))
    checked = benign_counts >= min_group_rows
    worst_domain_fpr = float(np.max(false_positives[checked] / benign_counts[checked])) if np.any(checked) else 0.0
    return dict(pooled=pooled, mean_fold_recall=float(np.mean([m["recall"] for m in fold_scores])),
        mean_fold_f1=float(np.mean([m["f1"] for m in fold_scores])),
        worst_fold_fpr=max(m["false_positive_rate"] for m in fold_scores),
        worst_large_domain_fpr=worst_domain_fpr, checked_benign_domains=int(np.sum(checked)))


def selection_key(summary, threshold, max_fpr, max_domain_fpr):
    """Only candidates meeting BOTH validation constraints are eligible.

    Maximize mean-fold recall, then lower worst-domain and pooled FPR, then
    higher threshold. These are validation targets, not deployment guarantees.
    """
    if (summary["pooled"]["false_positive_rate"] > max_fpr
            or summary["worst_large_domain_fpr"] > max_domain_fpr):
        return None
    return (summary["mean_fold_recall"], -summary["worst_large_domain_fpr"],
            -summary["pooled"]["false_positive_rate"], threshold)


def parameter_grid(seed, n_jobs):
    # Stronger regularization than v0.1; fixed before outer evaluation.
    return [dict(n_estimators=150, max_depth=depth, min_samples_leaf=leaf,
                 class_weight=weight, max_features="sqrt", random_state=seed, n_jobs=n_jobs)
            for depth, leaf, weight in itertools.product((8, 12), (5, 20), (None, "balanced_subsample"))]


def select_group_cv(x, y, groups, *, seed=42, n_jobs=2, n_splits=3,
                    max_fpr=0.01, max_domain_fpr=0.05, min_group_rows=100,
                    context="selection", configs=None, thresholds=THRESHOLDS):
    """Select on out-of-fold development predictions only; no test input."""
    if not 0 <= max_fpr <= 1 or not 0 <= max_domain_fpr <= 1:
        raise ValueError("False-positive targets must lie in [0, 1]")
    if min_group_rows < 1:
        raise ValueError("min_group_rows must be positive")
    if not thresholds or any(not 0 < t < 1 for t in thresholds):
        raise ValueError("Thresholds must be between zero and one")
    folds = domain_folds(y, groups, n_splits, seed)
    _, inverse = np.unique(groups, return_inverse=True)
    group_encoding = (inverse, np.bincount(inverse, weights=y == 0))
    trials, best, best_key = [], None, None
    grid = configs if configs is not None else parameter_grid(seed, n_jobs)
    for candidate_id, params in enumerate(grid, start=1):
        probabilities = np.full(len(y), np.nan)
        for fold_id, validation in enumerate(folds):
            training = np.setdiff1d(np.arange(len(y)), validation)
            if set(groups[training]) & set(groups[validation]):
                raise AssertionError("Domain leakage in CV")
            model = RandomForestClassifier(**params).fit(x[training], y[training])
            model.n_jobs = 1
            probabilities[validation] = model.predict_proba(x[validation])[:, 1]
        if not np.isfinite(probabilities).all():
            raise AssertionError("Each row must receive exactly one out-of-fold score")
        for threshold in thresholds:
            summary = validation_summary(y, probabilities, groups, folds, threshold, min_group_rows, group_encoding)
            key = selection_key(summary, threshold, max_fpr, max_domain_fpr)
            trials.append(dict(candidate_id=candidate_id, parameters=params, threshold=threshold,
                               eligible=key is not None, validation=summary))
            if key is not None and (best_key is None or key > best_key):
                best_key = key
                best = dict(candidate_id=candidate_id, parameters=params, decision_threshold=threshold,
                            validation=summary, probabilities=probabilities.copy())
        print(f"{context}: candidate {candidate_id}/{len(grid)} complete", flush=True)
    if best is None:
        raise ValueError("No model meets the validation FPR policy; refusing to publish a fallback model")
    best["domain_validation"] = group_metrics(y, best["probabilities"] >= best["decision_threshold"], groups)
    best["fold_assignments"] = {int(i): fold_id for fold_id, fold in enumerate(folds) for i in fold}
    return best, trials


def candidate_metadata(selected):
    return {key: selected[key] for key in
            ("candidate_id", "parameters", "decision_threshold", "validation", "domain_validation")}


def run(input_path, output_dir, seed=42, n_jobs=2, outer_splits=5, inner_splits=3,
        max_fpr=0.01, max_domain_fpr=0.05, min_group_rows=100):
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("Use an empty output directory to preserve previous experiments")
    records, removed = load_records(input_path)
    records.sort(key=lambda e: (e.record.epoch_time, e.row_id))
    rows, x, y = derive_features(records)
    groups = np.asarray([e.record.apex_domain for e in records])
    # All folds keep whole apex groups. Removing unrelated groups cannot change
    # a (client, apex) history, so causal features can be safely cached once.
    outer = domain_folds(y, groups, outer_splits, seed)
    outer_probabilities = np.full(len(y), np.nan)
    outer_predictions = np.full(len(y), -1, dtype=int)
    outer_assignment = np.full(len(y), -1, dtype=int)
    fold_reports = []
    selection_options = dict(seed=seed, n_jobs=n_jobs, n_splits=inner_splits,
        max_fpr=max_fpr, max_domain_fpr=max_domain_fpr, min_group_rows=min_group_rows)
    for fold_id, evaluation in enumerate(outer):
        development = np.setdiff1d(np.arange(len(y)), evaluation)
        print(f"Outer fold {fold_id + 1}/{outer_splits}: {len(development)} development, {len(evaluation)} evaluation rows", flush=True)
        selected, trials = select_group_cv(x[development], y[development], groups[development],
            context=f"outer {fold_id + 1} inner CV", **selection_options)
        # The outer labels/scores are never passed to selection.
        model = RandomForestClassifier(**selected["parameters"]).fit(x[development], y[development])
        model.n_jobs = 1
        probabilities = model.predict_proba(x[evaluation])[:, 1]
        predictions = (probabilities >= selected["decision_threshold"]).astype(int)
        outer_probabilities[evaluation] = probabilities
        outer_predictions[evaluation] = predictions
        outer_assignment[evaluation] = fold_id
        fold_reports.append(dict(fold=fold_id, development_rows=len(development), evaluation_rows=len(evaluation),
            evaluation_domains=len(set(groups[evaluation])), selection=candidate_metadata(selected),
            trials=trials, metrics=classification_metrics(y[evaluation], predictions, probabilities),
            domain_metrics=group_metrics(y[evaluation], predictions, groups[evaluation])))
        # Report progress without adapting any subsequent choices to its score.
        print(f"Outer fold {fold_id + 1}: FPR={fold_reports[-1]['metrics']['false_positive_rate']:.4f}, recall={fold_reports[-1]['metrics']['recall']:.4f}", flush=True)
    if not np.isfinite(outer_probabilities).all() or np.any(outer_assignment < 0):
        raise AssertionError("Incomplete nested evaluation")
    # Separate final selection uses all current DEVELOPMENT records. Its result
    # is not chosen by comparing outer scores and has no fresh final test set.
    selected, final_trials = select_group_cv(x, y, groups, context="final development CV", **selection_options)
    final_model = RandomForestClassifier(**selected["parameters"]).fit(x, y)
    final_model.n_jobs = 1
    bundle = dict(schema_version=1, model=final_model, feature_order=list(FEATURE_ORDER),
        decision_threshold=selected["decision_threshold"], window_seconds=60.0,
        first_query_time_interval=-1.0, classes=[0, 1], seed=seed, inference_n_jobs=1,
        input_sha256=sha256_file(input_path), sklearn_version=importlib.metadata.version("scikit-learn"),
        training_scope="all current development data; no independent final test", deployment_ready=False)
    joblib.dump(bundle, output_dir / "random_forest.joblib", compress=3)
    loaded = load_model(output_dir / "random_forest.joblib")
    _, saved_prob = predict_features(loaded, rows[:128])
    if not np.array_equal(saved_prob, final_model.predict_proba(x[:128])[:, 1]):
        raise AssertionError("Artifact reload mismatch")
    with (output_dir / "nested_predictions.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["input_row_id", "apex_domain", "outer_fold", "label", "prediction", "attack_probability"])
        writer.writerows((e.row_id, group, int(fold), int(label), int(pred), float(prob))
            for e, group, fold, label, pred, prob in zip(records, groups, outer_assignment, y, outer_predictions, outer_probabilities))
    with (output_dir / "final_selection_predictions.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["input_row_id", "validation_fold", "label", "attack_probability"])
        writer.writerows((e.row_id, selected["fold_assignments"][i], int(label), float(prob))
            for i, (e, label, prob) in enumerate(zip(records, y, selected["probabilities"])))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    report = dict(schema_version=2, created_at_utc=datetime.now(timezone.utc).isoformat(), seed=seed,
        input=dict(path=input_path.as_posix(), sha256=bundle["input_sha256"], rows=len(records),
                   duplicate_rows_removed=removed), feature_order=list(FEATURE_ORDER),
        environment=dict(python=platform.python_version(), packages={name:importlib.metadata.version(name)
            for name in ("scikit-learn", "numpy", "scipy", "joblib", "threadpoolctl", "narwhals", "cloudpickle")}),
        source=dict(git_head_at_run=commit, file_sha256={path.as_posix():sha256_file(path)
            for root in ("src/ml", "src/features", "src/preprocessing") for path in sorted(Path(root).glob("*.py"))}),
        protocol=dict(method="nested domain-disjoint cross-validation with domain-count-balanced folds",
            outer_splits=outer_splits, inner_splits=inner_splits, domain_overlap=0,
            max_validation_fpr=max_fpr, max_large_domain_fpr=max_domain_fpr,
            min_benign_rows_for_domain_constraint=min_group_rows,
            thresholds=list(THRESHOLDS), window_seconds=60.0,
            objective="maximize mean validation fold recall under pooled and large-domain FPR constraints; ties lower worst-domain FPR, lower pooled FPR, higher threshold"),
        nested_evaluation=dict(pooled=classification_metrics(y, outer_predictions),
            mean_fold_f1=float(np.mean([f["metrics"]["f1"] for f in fold_reports])),
            worst_fold_fpr=max(f["metrics"]["false_positive_rate"] for f in fold_reports),
            domain_metrics=group_metrics(y, outer_predictions, groups), folds=fold_reports),
        final_model=dict(selection=candidate_metadata(selected), trials=final_trials, trained_rows=len(records),
            feature_importances=dict(zip(FEATURE_ORDER,map(float, final_model.feature_importances_))),
            independent_test_available=False, deployment_ready=False),
        artifacts=dict(model_sha256=sha256_file(output_dir / "random_forest.joblib"),
            roundtrip_probabilities_identical=True),
        limitations=["All current data are development data following inspection of the v0.1 test set.",
            "Nested scores evaluate selection on existing data; they are not a fresh independent final test.",
            "FPR policy is a validation target, not a guarantee for unseen domains.",
            "Only ten synthetic attack domains; one capture environment; no new benign capture added.",
            "Class/domain coverage prioritized; row proportions vary with giant domains.",
            "Cloud-provider grouping and full-query feature semantics remain unchanged."])
    write_json(output_dir / "experiment.json", report)
    write_json(output_dir / "feature_order.json", dict(feature_order=list(FEATURE_ORDER),
        decision_threshold=selected["decision_threshold"], window_seconds=60.0,
        first_query_time_interval=-1.0, classes=[0,1]))
    print("Nested evaluation: " + json.dumps(report["nested_evaluation"]["pooled"]), flush=True)
    print("Final selected threshold: " + str(selected["decision_threshold"]), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/processed/cleaned_unified_v0.1.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/random_forest_v0.2"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-jobs", type=int, default=2)
    parser.add_argument("--outer-splits", type=int, default=5)
    parser.add_argument("--inner-splits", type=int, default=3)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--max-domain-fpr", type=float, default=0.05)
    parser.add_argument("--min-group-rows", type=int, default=100)
    args = parser.parse_args()
    run(args.input, args.output_dir, args.seed, args.n_jobs, args.outer_splits,
        args.inner_splits, args.max_fpr, args.max_domain_fpr, args.min_group_rows)


if __name__ == "__main__":
    main()
