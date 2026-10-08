"""Checks for partition leakage, feature contract and persisted inference."""

import csv
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from src.ml.artifact import load_model, predict_features
from src.ml.data import Example, derive_features, load_records, split_records
from src.ml.features import FEATURE_ORDER, feature_matrix
from src.ml.train import classification_metrics, select_forest
from src.preprocessing.pipeline import PreprocessingPipeline


def example(row_id, label=0, domain="example.com", host="10.0.0.1", seconds=0):
    record = PreprocessingPipeline().normalize_and_parse_record(
        PreprocessingPipeline().parse_csv_row_to_raw_record(dict(
            timestamp=str(1735689600 + seconds), src_ip=host, dst_ip="8.8.8.8",
            requested_server_name=domain, label=label)))
    return Example(row_id, record)


def test_exact_feature_contract_ignores_all_identifiers():
    expected = ["query_length", "longest_label_length", "number_of_labels", "entropy",
                "digit_ratio", "special_char_ratio", "subdomain_length", "query_frequency",
                "unique_subdomains", "time_interval"]
    assert list(FEATURE_ORDER) == expected
    row = {name: i for i, name in enumerate(reversed(expected))}
    row.update(src_ip="malicious-text", apex_domain="ignored", epoch_time=float("nan"), label=1)
    assert feature_matrix([row]).tolist() == [[row[name] for name in expected]]
    with pytest.raises(KeyError):
        feature_matrix([{"query_length": 20}])
    row["entropy"] = float("inf")
    with pytest.raises(ValueError, match="finite"):
        feature_matrix([row])


def test_split_keeps_apex_across_clients_disjoint_and_is_repeatable():
    records = [example(i * 2 + host + 1, i % 2, f"q{i}.domain{i}.com",
                       f"10.0.0.{host + 1}", i) for i in range(30) for host in range(2)]
    first = split_records(records, seed=42)
    second = split_records(records, seed=42)
    assert {name: [e.row_id for e in items] for name, items in first.items()} == {
        name: [e.row_id for e in items] for name, items in second.items()}
    assert sorted(e.row_id for items in first.values() for e in items) == list(range(1, 61))
    groups = [{e.record.apex_domain for e in items} for items in first.values()]
    assert all(not groups[i] & groups[j] for i in range(3) for j in range(i + 1, 3))
    assert all({e.record.label for e in items} == {0, 1} for items in first.values())


def test_insufficient_groups_fails_instead_of_falling_back_to_row_split():
    with pytest.raises(ValueError, match="five distinct"):
        split_records([example(1), example(2, 1)])


def test_behavioral_features_are_causal_and_reset_on_a_new_partition():
    history = [example(1, domain="one.example.com", seconds=0),
               example(2, domain="two.example.com", seconds=30),
               example(3, domain="three.example.com", seconds=61)]
    rows, matrix, labels = derive_features(history)
    assert [r["query_frequency"] for r in rows] == [1, 2, 2]
    assert [r["unique_subdomains"] for r in rows] == [1, 2, 2]
    assert [r["time_interval"] for r in rows] == [-1.0, 30.0, 31.0]
    prefix, _, _ = derive_features(history[:2])
    assert prefix == rows[:2]  # Adding future queries cannot change past features.
    fresh, _, _ = derive_features(history[1:])
    assert fresh[0]["time_interval"] == -1.0 and fresh[0]["query_frequency"] == 1
    assert matrix.shape == (3, 10)


def write_input(path, labels):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "src_ip", "dst_ip", "requested_server_name", "label"])
        writer.writeheader()
        for label in labels:
            writer.writerow(dict(timestamp="2025-01-01 00:00:00", src_ip="10.0.0.1",
                                 dst_ip="8.8.8.8", requested_server_name="Q.Example.COM.", label=label))


def test_loader_deduplicates_normalized_events_and_rejects_conflicting_labels(tmp_path):
    path = tmp_path / "records.csv"
    write_input(path, [0, 0])
    records, removed = load_records(path)
    assert len(records) == 1 and removed == [2]
    write_input(path, [0, 1])
    with pytest.raises(ValueError, match="Conflicting labels"):
        load_records(path)
    write_input(path, [0.5])
    with pytest.raises(ValueError, match="exactly 0 or 1"):
        load_records(path)


def test_metrics_confusion_matrix_and_zero_prediction_denominators():
    metrics = classification_metrics([0, 0, 1, 1], [0, 1, 0, 1])
    assert metrics["confusion_matrix"] == [[1, 1], [1, 1]]
    assert metrics["f1"] == 0.5 and metrics["false_positive_rate"] == 0.5
    assert classification_metrics([0, 1], [0, 0])["precision"] == 0.0


def test_artifact_roundtrip_preserves_probabilities_and_selected_threshold(tmp_path):
    rows = [{name: float(i % 2) for name in FEATURE_ORDER} for i in range(12)]
    matrix = feature_matrix(rows)
    model = RandomForestClassifier(n_estimators=5, random_state=42).fit(matrix, [i % 2 for i in range(12)])
    bundle = dict(schema_version=1, feature_order=list(FEATURE_ORDER), model=model, decision_threshold=0.7)
    path = tmp_path / "model.joblib"
    joblib.dump(bundle, path)
    loaded = load_model(path)
    predictions, probabilities = predict_features(loaded, rows)
    assert np.array_equal(probabilities, model.predict_proba(matrix)[:, 1])
    assert np.array_equal(predictions, probabilities >= 0.7)
    bundle["feature_order"] = list(reversed(FEATURE_ORDER))
    joblib.dump(bundle, path)
    with pytest.raises(ValueError, match="feature order"):
        load_model(path)


def test_forest_selection_repeatable_and_fitted_on_training_only():
    x_train = np.asarray([[i % 2] * 10 for i in range(20)], dtype=float)
    y_train = np.asarray([i % 2 for i in range(20)])
    x_validation, y_validation = x_train[:6], y_train[:6]
    first, trials = select_forest(x_train, y_train, x_validation, y_validation)
    second, repeat = select_forest(x_train, y_train, x_validation, y_validation)
    assert trials == repeat and len(trials) == 24
    assert first["parameters"] == second["parameters"]
    assert first["decision_threshold"] == second["decision_threshold"]
    # Every tree bootstraps only the 20 training rows, never validation rows.
    assert all(len(indexes) == len(y_train) and max(indexes) < len(y_train)
               for indexes in first["model"].estimators_samples_)
