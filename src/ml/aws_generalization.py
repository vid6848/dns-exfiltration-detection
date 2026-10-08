"""Frozen AWS-domain diagnostic with independent public benign development data.

The v0.2 outer-fold allocation is reused for an explicit, comparable diagnostic.
All evaluation apex domains are excluded from every imported capture before
inner selection. This is development work, not a fresh final test claim.
"""

import argparse
import csv
import importlib.metadata
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from .artifact import load_model, predict_features
from .data import derive_features, load_records
from .features import FEATURE_ORDER
from .robust_train import candidate_metadata, group_metrics, select_group_cv
from .train import classification_metrics, sha256_file, write_json


def heldout_partition(records, prediction_path, fold=4):
    with prediction_path.open(encoding='utf-8', newline='') as stream:
        evidence = {int(r['input_row_id']): r for r in csv.DictReader(stream)}
    if set(evidence) != {e.row_id for e in records}:
        raise ValueError('Baseline allocation does not cover exactly the input rows')
    for e in records:
        r = evidence[e.row_id]
        if r['apex_domain'] != e.record.apex_domain or int(r['label']) != e.record.label:
            raise ValueError('Baseline allocation does not match the input data')
    evaluation = [e for e in records if int(evidence[e.row_id]['outer_fold']) == fold]
    excluded = {e.record.apex_domain for e in evaluation}
    evaluation_ids = {e.row_id for e in evaluation}
    training = [e for e in records if e.record.apex_domain not in excluded]
    if 'amazonaws.com' not in excluded:
        raise ValueError('Chosen evaluation fold must contain the AWS apex')
    for e in records:
        if (e.record.apex_domain in excluded) != (e.row_id in evaluation_ids):
            raise ValueError('Baseline allocation splits an apex domain')
    return training, evaluation, excluded, evidence


def filter_benign_capture(records, excluded):
    if any(e.record.label != 0 for e in records):
        raise ValueError('Public benign input contains non-benign labels')
    accepted = [e for e in records if e.record.apex_domain not in excluded]
    if not accepted:
        raise ValueError('No imported queries remain after held-out-domain exclusion')
    return sorted(accepted, key=lambda e: (e.record.epoch_time, e.row_id))


def run(input_path, benign_paths, output_dir, baseline_dir, n_jobs=2):
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError('Use an empty output directory')
    baseline_log = json.loads((baseline_dir / 'experiment.json').read_text(encoding='utf-8'))
    if sha256_file(input_path) != baseline_log['input']['sha256']:
        raise ValueError('Input differs from frozen v0.2 allocation')
    records, removed = load_records(input_path)
    training, evaluation, excluded, evidence = heldout_partition(
        records, baseline_dir / 'nested_predictions.csv')
    training.sort(key=lambda e: (e.record.epoch_time, e.row_id))
    evaluation.sort(key=lambda e: (e.record.epoch_time, e.row_id))
    train_rows, x_train, y_train = derive_features(training)
    groups = np.asarray([e.record.apex_domain for e in training])
    inputs = []
    capture_hashes = set()
    for path in benign_paths:
        provenance_path = path.with_suffix('.provenance.json')
        provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
        if sha256_file(path) != provenance['output_sha256']:
            raise ValueError('Public input does not match importer provenance')
        if provenance['capture_sha256'] in capture_hashes:
            raise ValueError('The same public capture cannot be imported twice')
        capture_hashes.add(provenance['capture_sha256'])
        imported, duplicates = load_records(path)
        accepted = filter_benign_capture(imported, excluded)
        # Independent captures get independent behavioral histories. In
        # particular, identical private IPs from unrelated networks cannot mix.
        rows, matrix, labels = derive_features(accepted)
        train_rows.extend(rows)
        x_train = np.concatenate((x_train, matrix))
        y_train = np.concatenate((y_train, labels))
        groups = np.concatenate((groups, [e.record.apex_domain for e in accepted]))
        inputs.append(dict(path=path.as_posix(), sha256=sha256_file(path),
            provenance=provenance, imported_rows=len(imported), retained_rows=len(accepted),
            excluded_heldout_domain_rows=len(imported)-len(accepted), duplicates_removed=duplicates,
            feature_quantiles={name: {str(q): float(np.quantile(matrix[:, i], q)) for q in (.5, .95, .99)}
                for i, name in enumerate(FEATURE_ORDER)}))
        print(f'Imported {len(accepted):,} benign queries; excluded {len(imported)-len(accepted):,} held-out-domain queries', flush=True)
    if set(groups) & excluded:
        raise AssertionError('Evaluation apex leaked into development')
    print(f'Selecting using {len(y_train):,} development rows; AWS and all {len(excluded)} evaluation apexes excluded', flush=True)
    selected, trials = select_group_cv(x_train, y_train, groups, n_jobs=n_jobs,
        context='AWS-excluded augmented development CV')
    model = RandomForestClassifier(**selected['parameters']).fit(x_train, y_train)
    model.n_jobs = 1
    eval_rows, x_eval, y_eval = derive_features(evaluation)
    probabilities = model.predict_proba(x_eval)[:, 1]
    predictions = (probabilities >= selected['decision_threshold']).astype(int)
    eval_groups = np.asarray([e.record.apex_domain for e in evaluation])
    old_predictions = np.asarray([int(evidence[e.row_id]['prediction']) for e in evaluation])
    aws = eval_groups == 'amazonaws.com'
    bundle = dict(schema_version=1, model=model, feature_order=list(FEATURE_ORDER),
        decision_threshold=selected['decision_threshold'], window_seconds=60.0,
        first_query_time_interval=-1.0, classes=[0, 1], inference_n_jobs=1,
        sklearn_version=importlib.metadata.version('scikit-learn'), deployment_ready=False,
        training_scope='Development diagnostic: v0.2 outer fold 5 excluded; added independent public benign captures',
        excluded_evaluation_domains=sorted(excluded))
    joblib.dump(bundle, output_dir / 'random_forest.joblib', compress=3)
    loaded = load_model(output_dir / 'random_forest.joblib')
    restored, restored_prob = predict_features(loaded, eval_rows)
    if not np.array_equal(restored_prob, probabilities) or not np.array_equal(restored, predictions):
        raise AssertionError('Artifact roundtrip mismatch')
    with (output_dir / 'diagnostic_predictions.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['input_row_id', 'apex_domain', 'label', 'baseline_prediction', 'prediction', 'attack_probability'])
        writer.writerows((e.row_id, g, int(y), int(old), int(pred), float(p)) for
            e, g, y, old, pred, p in zip(evaluation, eval_groups, y_eval, old_predictions, predictions, probabilities))
    report = dict(feature_order=list(FEATURE_ORDER), input_path=input_path.as_posix(), input_sha256=sha256_file(input_path),
        baseline_prediction_sha256=sha256_file(baseline_dir / 'nested_predictions.csv'),
        duplicates_removed=removed, public_inputs=inputs,
        source_sha256={p.as_posix(): sha256_file(p) for root in ('src/ml', 'src/features', 'src/preprocessing') for p in sorted(Path(root).glob('*.py'))},
        training_rows=len(y_train), training_benign=int(np.sum(y_train == 0)), training_attack=int(np.sum(y_train == 1)),
        evaluation_rows=len(y_eval), evaluation_domains=sorted(excluded),
        evaluation_domain_overlap=len(set(groups) & excluded), aws_training_rows=int(np.sum(groups == 'amazonaws.com')),
        selection=candidate_metadata(selected), trials=trials,
        baseline=dict(pooled=classification_metrics(y_eval, old_predictions),
                      aws=classification_metrics(y_eval[aws], old_predictions[aws])),
        augmented=dict(pooled=classification_metrics(y_eval, predictions, probabilities),
                       aws=classification_metrics(y_eval[aws], predictions[aws]),
                       domain_metrics=group_metrics(y_eval, predictions, eval_groups)),
        artifact=dict(sha256=sha256_file(output_dir / 'random_forest.joblib'), roundtrip_identical=True),
        environment={name: importlib.metadata.version(name) for name in ('scikit-learn', 'numpy', 'joblib', 'scapy')},
        limitations=['AWS diagnostic labels and earlier results have already been inspected; no fresh final test claim',
                     'Selection uses inner domain-disjoint development scores only; no AWS scores select thresholds',
                     'Only synthetic attack campaigns in the primary input; independent real attack evaluation still needed',
                     'Public benign ground truth comes from publisher provenance',
                     'Different private-IP networks get separate behavioral histories; no raw metadata enters RF'])
    write_json(output_dir / 'experiment.json', report)
    write_json(output_dir / 'feature_order.json', dict(feature_order=list(FEATURE_ORDER),
        decision_threshold=selected['decision_threshold'], window_seconds=60.0, first_query_time_interval=-1.0))
    result = {k: report[k] for k in ('baseline', 'augmented')}
    result['augmented'] = {k: v for k, v in result['augmented'].items() if k != 'domain_metrics'}
    print(json.dumps(result, indent=2), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('data/processed/cleaned_unified_v0.1.csv'))
    parser.add_argument('--benign', type=Path, nargs='+', required=True)
    parser.add_argument('--baseline-dir', type=Path, default=Path('artifacts/random_forest_v0.2'))
    parser.add_argument('--output-dir', type=Path, default=Path('artifacts/aws_benign_expansion_v0.1'))
    parser.add_argument('--n-jobs', type=int, default=2)
    args = parser.parse_args()
    run(args.input, args.benign, args.output_dir, args.baseline_dir, args.n_jobs)


if __name__ == '__main__':
    main()
