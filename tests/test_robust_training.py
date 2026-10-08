"""Regression checks for representative grouping and conservative selection."""

import numpy as np
import pytest

from src.ml.data import Example, derive_features
from src.ml.group_cv import domain_folds
from src.ml.robust_train import group_metrics, select_group_cv, selection_key, validation_summary
from src.preprocessing.pipeline import PreprocessingPipeline


def test_giant_cloud_group_does_not_exclude_other_benign_domains_from_its_fold():
    labels, groups = [], []
    for label in (0, 1):
        for i in range(15):
            size = 1000 if label == 0 and i == 0 else 4
            labels.extend([label] * size)
            groups.extend([f"class{label}-domain{i}.com"] * size)
    labels, groups = np.asarray(labels), np.asarray(groups)
    folds = domain_folds(labels, groups, 5, seed=42)
    assert sorted(np.concatenate(folds).tolist()) == list(range(len(labels)))
    for indexes in folds:
        assert len(set(groups[indexes][labels[indexes] == 0])) == 3
        assert len(set(groups[indexes][labels[indexes] == 1])) == 3
        other = np.setdiff1d(np.arange(len(labels)), indexes)
        assert not set(groups[indexes]) & set(groups[other])
    assert all(np.array_equal(a, b) for a, b in zip(folds, domain_folds(labels, groups, 5, seed=42)))


def test_mixed_label_domains_stay_intact():
    groups = np.repeat([f"domain{i}.com" for i in range(12)], 5)
    labels = np.array([0, 0, 0, 1, 1] * 6 + [1, 1, 1, 0, 0] * 6)
    folds = domain_folds(labels, groups, 3)
    for group in np.unique(groups):
        assert sum(group in set(groups[fold]) for fold in folds) == 1


def test_too_few_domains_fails_instead_of_leaking_groups():
    with pytest.raises(ValueError, match="distinct domains"):
        domain_folds(np.array([0, 1]), np.array(["one.com", "two.com"]), 3)


def test_group_error_report_includes_small_domains_and_mixed_labels():
    result = group_metrics([0, 0, 1, 0], [1, 0, 0, 1], ["a", "a", "a", "b"])
    a, b = result
    assert a["false_positive_rate"] == 0.5 and a["recall"] == 0.0
    assert b["false_positive_rate"] == 1.0 and b["benign"] == 1


def test_large_domain_constraint_catches_error_hidden_by_pooled_fpr():
    labels = np.array([0] * 1000 + [0] * 100 + [1] * 100)
    groups = np.array(["easy"] * 1000 + ["cloud"] * 100 + ["attack"] * 100)
    probabilities = np.array([0.0] * 1000 + [0.9] * 10 + [0.0] * 90 + [1.0] * 100)
    folds = [np.r_[np.arange(0, 550), np.arange(1100, 1150)],
             np.r_[np.arange(550, 1100), np.arange(1150, 1200)]]
    summary = validation_summary(labels, probabilities, groups, folds, 0.5)
    assert summary["pooled"]["false_positive_rate"] < 0.01
    assert summary["worst_large_domain_fpr"] == 0.1
    assert selection_key(summary, 0.5, 0.01, 0.05) is None


def test_equal_validation_results_prefer_higher_threshold():
    summary = dict(pooled={"false_positive_rate": 0.0}, worst_large_domain_fpr=0.0, mean_fold_recall=1.0)
    assert selection_key(summary, 0.9, 0.01, 0.05) > selection_key(summary, 0.5, 0.01, 0.05)


def test_cv_scores_are_repeatable_and_threshold_selection_is_conservative():
    groups = np.repeat([f"domain{i}.com" for i in range(12)], 4)
    labels = np.repeat([i % 2 for i in range(12)], 4)
    x = np.repeat(labels[:, None], 10, axis=1)
    params = [dict(n_estimators=10, max_depth=3, min_samples_leaf=1, random_state=42, n_jobs=1)]
    first, trials = select_group_cv(x, labels, groups, configs=params, thresholds=(0.5, 0.9), min_group_rows=1)
    second, repeat = select_group_cv(x, labels, groups, configs=params, thresholds=(0.5, 0.9), min_group_rows=1)
    assert first["decision_threshold"] == 0.9
    assert np.array_equal(first["probabilities"], second["probabilities"])
    assert trials == repeat and all(t["eligible"] for t in trials)


def test_causal_feature_cache_equals_independent_fold_histories():
    pipeline = PreprocessingPipeline()
    records = []
    for i in range(30):
        record = pipeline.normalize_and_parse_record(pipeline.parse_csv_row_to_raw_record(dict(
            timestamp=str(1735689600 + i * 10), src_ip="10.0.0.1", dst_ip="8.8.8.8",
            requested_server_name=f"query{i}.domain{i % 6}.com", label=i % 2)))
        records.append(Example(i + 1, record))
    _, cached, labels = derive_features(records)
    groups = np.array([e.record.apex_domain for e in records])
    for fold in domain_folds(labels, groups, 3):
        _, independent, _ = derive_features([records[int(i)] for i in fold])
        assert np.array_equal(cached[fold], independent)
