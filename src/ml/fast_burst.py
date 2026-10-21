"""Fast-burst remediation on top of the frozen AWS diagnostic.

The v0.1 synthetic attacks never send consecutive queries less than 50 ms apart
(burst gaps were drawn from 50-1500 ms), while 3.5% of real benign gaps are that
short. The AWS-expansion forest therefore learned "very fast = benign" and scores
a tunnel tool sending at full speed below threshold.

This experiment keeps everything else fixed: the same input CSV and frozen
v0.2 outer fold 5 as the evaluation population, the same public benign capture,
the same eight RF configurations, inner domain-disjoint CV and FPR policy. The
only change is extra development data: fast-burst attack campaigns (2-50 ms
gaps) on attacker domains that appear nowhere in the evaluation fold.

Two further checks answer whether the fix works and what it costs:
  * stress test: separately generated fast-burst campaigns on unseen domains;
  * timing sweep: the same stress queries re-timed at fixed gaps (1 ms - 1 s);
and false positives are reported for benign evaluation queries whose gap to
the previous query in their group is under 50 ms.
"""

import argparse
import csv
import importlib.metadata
import json
from dataclasses import replace
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from .artifact import load_model, predict_features
from .aws_generalization import filter_benign_capture, heldout_partition
from .data import derive_features, load_records
from .features import FEATURE_ORDER
from .robust_train import candidate_metadata, group_metrics, select_group_cv
from .train import classification_metrics, sha256_file, write_json


FAST_GAP_SECONDS = 0.05
SWEEP_GAPS_MS = (1, 5, 10, 20, 35, 50, 100, 250, 1000)


def load_public_benign(path, excluded, seen_captures):
    provenance = json.loads(path.with_suffix('.provenance.json').read_text(encoding='utf-8'))
    if sha256_file(path) != provenance['output_sha256']:
        raise ValueError('Public input does not match importer provenance')
    if provenance['capture_sha256'] in seen_captures:
        raise ValueError('The same public capture cannot be imported twice')
    seen_captures.add(provenance['capture_sha256'])
    imported, _ = load_records(path)
    return filter_benign_capture(imported, excluded), provenance


def load_attack_capture(path, excluded):
    """Synthetic attack campaigns for development; must not touch evaluation domains."""
    records, duplicates = load_records(path)
    if any(e.record.label != 1 for e in records):
        raise ValueError('Fast-burst attack input contains non-attack labels')
    overlap = {e.record.apex_domain for e in records} & excluded
    if overlap:
        raise ValueError(f'Attack input reuses evaluation domains: {sorted(overlap)}')
    return sorted(records, key=lambda e: (e.record.epoch_time, e.row_id)), duplicates


def retime(examples, gap_seconds):
    """Same queries, same per-(client, apex) order, fixed gap between queries of a group."""
    examples = sorted(examples, key=lambda e: (e.record.epoch_time, e.row_id))
    next_time = {}
    timed = []
    for e in examples:
        key = (e.record.src_ip, e.record.apex_domain)
        t = next_time.get(key, 1_700_000_000.0)
        next_time[key] = t + gap_seconds
        timed.append(replace(e, record=replace(e.record, epoch_time=t)))
    return sorted(timed, key=lambda e: (e.record.epoch_time, e.row_id))


def recall(bundle, examples):
    rows, _, _ = derive_features(examples)
    predictions, probabilities = predict_features(bundle, rows)
    return float(np.mean(predictions)), probabilities, rows


def run(input_path, benign_paths, attack_path, stress_path, output_dir, baseline_dir,
        previous_dir, n_jobs=2):
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

    # Every capture gets its own causal behavioral history, as in the AWS experiment.
    blocks = [derive_features(training)]
    groups = [np.asarray([e.record.apex_domain for e in training])]
    inputs, seen_captures = [], set()
    for path in benign_paths:
        accepted, provenance = load_public_benign(path, excluded, seen_captures)
        blocks.append(derive_features(accepted))
        groups.append(np.asarray([e.record.apex_domain for e in accepted]))
        inputs.append(dict(kind='public_benign', path=path.as_posix(), sha256=sha256_file(path),
                           capture_sha256=provenance['capture_sha256'], retained_rows=len(accepted)))
    attacks, attack_duplicates = load_attack_capture(attack_path, excluded)
    attack_rows, attack_x, attack_y = derive_features(attacks)
    blocks.append((attack_rows, attack_x, attack_y))
    groups.append(np.asarray([e.record.apex_domain for e in attacks]))
    attack_gaps = np.asarray([r['time_interval'] for r in attack_rows])
    inputs.append(dict(kind='synthetic_fast_burst_attack', path=attack_path.as_posix(),
                       sha256=sha256_file(attack_path), rows=len(attacks), duplicates_removed=attack_duplicates,
                       domains=sorted({e.record.apex_domain for e in attacks}),
                       share_of_gaps_under_50ms=float(np.mean((attack_gaps >= 0) & (attack_gaps < FAST_GAP_SECONDS)))))

    x_train = np.concatenate([b[1] for b in blocks])
    y_train = np.concatenate([b[2] for b in blocks])
    groups = np.concatenate(groups)
    if set(groups) & excluded:
        raise AssertionError('Evaluation apex leaked into development')
    print(f'Selecting using {len(y_train):,} development rows ({int(np.sum(y_train))} attacks); '
          f'{len(excluded)} evaluation apexes excluded', flush=True)
    selected, trials = select_group_cv(x_train, y_train, groups, n_jobs=n_jobs,
                                       context='fast-burst augmented development CV')
    model = RandomForestClassifier(**selected['parameters']).fit(x_train, y_train)
    model.n_jobs = 1

    bundle = dict(schema_version=1, model=model, feature_order=list(FEATURE_ORDER),
        decision_threshold=selected['decision_threshold'], window_seconds=60.0,
        first_query_time_interval=-1.0, classes=[0, 1], inference_n_jobs=1,
        sklearn_version=importlib.metadata.version('scikit-learn'), deployment_ready=False,
        training_scope='Development diagnostic: v0.2 outer fold 5 excluded; public benign capture '
                       'and fast-burst synthetic campaigns added to development',
        excluded_evaluation_domains=sorted(excluded))
    joblib.dump(bundle, output_dir / 'random_forest.joblib', compress=3)
    bundle = load_model(output_dir / 'random_forest.joblib')
    previous = load_model(previous_dir / 'random_forest.joblib')

    # Frozen diagnostic population, scored once.
    eval_rows, x_eval, y_eval = derive_features(evaluation)
    predictions, probabilities = predict_features(bundle, eval_rows)
    if not np.array_equal(probabilities, model.predict_proba(x_eval)[:, 1]):
        raise AssertionError('Artifact roundtrip mismatch')
    previous_predictions, previous_probabilities = predict_features(previous, eval_rows)
    eval_groups = np.asarray([e.record.apex_domain for e in evaluation])
    gaps = np.asarray([r['time_interval'] for r in eval_rows])
    fast_benign = (y_eval == 0) & (gaps >= 0) & (gaps < FAST_GAP_SECONDS)
    aws = eval_groups == 'amazonaws.com'
    with (output_dir / 'diagnostic_predictions.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['input_row_id', 'apex_domain', 'label', 'previous_prediction', 'prediction', 'attack_probability'])
        writer.writerows((e.row_id, g, int(y), int(old), int(pred), float(p)) for
            e, g, y, old, pred, p in zip(evaluation, eval_groups, y_eval, previous_predictions, predictions, probabilities))

    # Stress test on unseen fast-burst domains, plus the fixed-gap sweep.
    stress, stress_duplicates = load_attack_capture(stress_path, excluded)
    overlap = {e.record.apex_domain for e in stress} & set(groups)
    if overlap:
        raise ValueError(f'Stress domains were used in development: {sorted(overlap)}')
    stress_recall, stress_prob, _ = recall(bundle, stress)
    stress_recall_previous, stress_prob_previous, _ = recall(previous, stress)
    sweep = []
    for gap_ms in SWEEP_GAPS_MS:
        timed = retime(stress, gap_ms / 1000)
        sweep.append(dict(gap_ms=gap_ms, previous_recall=recall(previous, timed)[0], recall=recall(bundle, timed)[0]))
        print(f'gap {gap_ms:>4} ms: recall {sweep[-1]["previous_recall"]:.3f} -> {sweep[-1]["recall"]:.3f}', flush=True)
    with (output_dir / 'stress_predictions.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['input_row_id', 'apex_domain', 'previous_attack_probability', 'attack_probability'])
        writer.writerows((e.row_id, e.record.apex_domain, float(old), float(new))
                         for e, old, new in zip(stress, stress_prob_previous, stress_prob))
    with (output_dir / 'timing_sweep.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['gap_ms', 'previous_recall', 'recall'])
        writer.writeheader()
        writer.writerows(sweep)

    threshold = bundle['decision_threshold']
    report = dict(feature_order=list(FEATURE_ORDER), input_path=input_path.as_posix(),
        input_sha256=sha256_file(input_path), duplicates_removed=removed,
        previous_model=dict(path=(previous_dir / 'random_forest.joblib').as_posix(),
                            sha256=sha256_file(previous_dir / 'random_forest.joblib'),
                            decision_threshold=previous['decision_threshold']),
        development_inputs=inputs, training_rows=len(y_train), training_benign=int(np.sum(y_train == 0)),
        training_attack=int(np.sum(y_train == 1)), evaluation_rows=len(y_eval),
        evaluation_domains=sorted(excluded), evaluation_domain_overlap=len(set(groups) & excluded),
        selection=candidate_metadata(selected), trials=trials,
        previous=dict(pooled=classification_metrics(y_eval, previous_predictions, previous_probabilities),
                      aws=classification_metrics(y_eval[aws], previous_predictions[aws]),
                      fast_benign_false_positives=int(np.sum(previous_predictions[fast_benign]))),
        augmented=dict(pooled=classification_metrics(y_eval, predictions, probabilities),
                       aws=classification_metrics(y_eval[aws], predictions[aws]),
                       domain_metrics=group_metrics(y_eval, predictions, eval_groups),
                       fast_benign_false_positives=int(np.sum(predictions[fast_benign]))),
        fast_benign_evaluation_rows=int(np.sum(fast_benign)),
        stress_test=dict(path=stress_path.as_posix(), sha256=sha256_file(stress_path), rows=len(stress),
                         duplicates_removed=stress_duplicates, domains=sorted({e.record.apex_domain for e in stress}),
                         previous_recall=stress_recall_previous, recall=stress_recall,
                         previous_threshold=previous['decision_threshold'], threshold=threshold),
        timing_sweep=sweep,
        artifact=dict(sha256=sha256_file(output_dir / 'random_forest.joblib'), roundtrip_identical=True),
        environment={name: importlib.metadata.version(name) for name in ('scikit-learn', 'numpy', 'joblib')},
        limitations=['Evaluation fold 5 was inspected in earlier experiments; diagnostic, not a fresh final test',
                     'All attack traffic, including the fast-burst campaigns and stress test, is synthetic',
                     'The evaluation fold contains no fast-burst attacks; the stress test and sweep measure that case',
                     'Selection uses inner domain-disjoint development scores only'])
    write_json(output_dir / 'experiment.json', report)
    write_json(output_dir / 'feature_order.json', dict(feature_order=list(FEATURE_ORDER),
        decision_threshold=threshold, window_seconds=60.0, first_query_time_interval=-1.0))
    summary = {k: {m: v for m, v in report[k].items() if m != 'domain_metrics'} for k in ('previous', 'augmented')}
    summary['stress_test'] = {k: report['stress_test'][k] for k in ('previous_recall', 'recall')}
    print(json.dumps(summary, indent=2), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', type=Path, default=Path('data/processed/cleaned_unified_v0.1.csv'))
    parser.add_argument('--benign', type=Path, nargs='+', required=True)
    parser.add_argument('--attack', type=Path, default=Path('data/processed/synthetic_fast_burst_train_v0.2.csv'))
    parser.add_argument('--stress', type=Path, default=Path('data/processed/synthetic_fast_burst_stress_v0.2.csv'))
    parser.add_argument('--baseline-dir', type=Path, default=Path('artifacts/random_forest_v0.2'))
    parser.add_argument('--previous-dir', type=Path, default=Path('artifacts/aws_benign_expansion_v0.1'))
    parser.add_argument('--output-dir', type=Path, default=Path('artifacts/fast_burst_v0.1'))
    parser.add_argument('--n-jobs', type=int, default=2)
    args = parser.parse_args()
    run(args.input, args.benign, args.attack, args.stress, args.output_dir, args.baseline_dir,
        args.previous_dir, args.n_jobs)


if __name__ == '__main__':
    main()
