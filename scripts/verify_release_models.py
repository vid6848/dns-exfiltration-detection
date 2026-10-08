"""Recompute saved RF predictions from canonical raw events before release.

Whole-apex partitions allow one chronological feature cache: no client/apex
history crosses either evaluation boundary. No model is fitted or retuned.
"""

import csv
import json
from pathlib import Path

import numpy as np

from src.ml.artifact import load_model, predict_features
from src.ml.data import derive_features, load_records
from src.ml.features import FEATURE_ORDER
from src.ml.train import classification_metrics, sha256_file, write_json


def verify():
    source = Path('data/processed/cleaned_unified_v0.1.csv')
    records, duplicates = load_records(source)
    records.sort(key=lambda e: (e.record.epoch_time, e.row_id))
    features, _, _ = derive_features(records)
    lookup = {e.row_id: (e, f) for e, f in zip(records, features)}
    results = {}
    for name, filename in (
        ('random_forest_v0.1', 'test_predictions.csv'),
        ('aws_benign_expansion_v0.1', 'diagnostic_predictions.csv'),
    ):
        directory = Path('artifacts') / name
        log = json.loads((directory / 'experiment.json').read_text(encoding='utf-8'))
        bundle = load_model(directory / 'random_forest.joblib')
        with (directory / filename).open(encoding='utf-8', newline='') as stream:
            saved = list(csv.DictReader(stream))
        ids = [int(r['input_row_id']) for r in saved]
        selected = [lookup[i] for i in ids]
        groups = {e.record.apex_domain for e, _ in selected}
        if len(ids) != len(set(ids)):
            raise AssertionError('Duplicate evaluation rows')
        if {e.row_id for e in records if e.record.apex_domain in groups} != set(ids):
            raise AssertionError('Evaluation does not contain complete apex histories')
        predictions, probabilities = predict_features(bundle, [f for _, f in selected])
        labels = np.array([e.record.label for e, _ in selected])
        expected_labels = np.array([int(r['label']) for r in saved])
        expected_predictions = np.array([int(r['prediction']) for r in saved])
        expected_probabilities = np.array([float(r['attack_probability']) for r in saved])
        metrics = classification_metrics(labels, predictions, probabilities)
        if name == 'random_forest_v0.1':
            expected_metrics = log['random_forest']['test']
            model_hash = log['artifacts']['model_sha256']
            input_hash = log['input']['sha256']
        else:
            expected_metrics = log['augmented']['pooled']
            model_hash = log['artifact']['sha256']
            input_hash = log['input_sha256']
        checks = dict(
            input_hash_matches=sha256_file(source) == input_hash,
            model_hash_matches=sha256_file(directory / 'random_forest.joblib') == model_hash,
            exact_feature_order=tuple(bundle['feature_order']) == FEATURE_ORDER,
            complete_apex_histories=True,
            labels_identical=np.array_equal(labels, expected_labels),
            predictions_identical=np.array_equal(predictions, expected_predictions),
            probabilities_bitwise_identical=np.array_equal(probabilities, expected_probabilities),
            metrics_identical=metrics == expected_metrics,
        )
        if not all(checks.values()):
            raise AssertionError({name: checks})
        results[name] = dict(rows=len(saved), checks=checks, metrics=metrics)
        print(f'{name}: all {len(saved):,} saved probabilities and predictions reproduced exactly', flush=True)
    report = dict(input_sha256=sha256_file(source), duplicate_rows_removed=duplicates,
        feature_order=list(FEATURE_ORDER), models=results,
        scope='Fresh execution of software/artifact checks on existing evaluation records; no new independent dataset or retraining')
    output = Path('artifacts/final_validation/model_replay.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, report)
    return report


if __name__ == '__main__':
    verify()
