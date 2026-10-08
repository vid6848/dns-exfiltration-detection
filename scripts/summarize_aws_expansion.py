"""Verify the AWS expansion diagnostic and render its readable report."""

import argparse
import csv
import json
from pathlib import Path

import numpy as np

from src.ml.artifact import load_model
from src.ml.features import FEATURE_ORDER
from src.ml.train import classification_metrics, sha256_file, write_json


def summarize(directory):
    log = json.loads((directory / 'experiment.json').read_text(encoding='utf-8'))
    bundle = load_model(directory / 'random_forest.joblib')
    with (directory / 'diagnostic_predictions.csv').open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    labels = np.array([int(r['label']) for r in rows])
    old = np.array([int(r['baseline_prediction']) for r in rows])
    new = np.array([int(r['prediction']) for r in rows])
    probabilities = np.array([float(r['attack_probability']) for r in rows])
    aws = np.array([r['apex_domain'] == 'amazonaws.com' for r in rows])
    checks = dict(
        model_hash_matches=sha256_file(directory / 'random_forest.joblib') == log['artifact']['sha256'],
        input_hash_matches=sha256_file(Path(log['input_path'])) == log['input_sha256'],
        source_hashes_match=all(sha256_file(Path(p)) == digest for p, digest in log['source_sha256'].items()),
        public_input_hashes_match=all(sha256_file(Path(r['path'])) == r['sha256'] for r in log['public_inputs']),
        aws_excluded_from_training=log['aws_training_rows'] == 0,
        all_evaluation_domains_excluded=log['evaluation_domain_overlap'] == 0,
        feature_order_exact=tuple(bundle['feature_order']) == FEATURE_ORDER,
        threshold_matches=bundle['decision_threshold'] == log['selection']['decision_threshold'],
        prediction_threshold_matches=np.array_equal(new, probabilities >= bundle['decision_threshold']),
        unique_complete_evaluation_rows=len(rows) == log['evaluation_rows'] == len({r['input_row_id'] for r in rows}),
        baseline_metrics_match=classification_metrics(labels, old) == log['baseline']['pooled'],
        augmented_metrics_match=classification_metrics(labels, new, probabilities) == log['augmented']['pooled'],
        aws_metrics_match=classification_metrics(labels[aws], new[aws]) == log['augmented']['aws'],
        validation_policy_met=log['selection']['validation']['pooled']['false_positive_rate'] <= .01
            and log['selection']['validation']['worst_large_domain_fpr'] <= .05,
        roundtrip_identical=log['artifact']['roundtrip_identical'],
        marked_development_only=bundle['deployment_ready'] is False,
    )
    if not all(checks.values()):
        raise AssertionError(checks)
    write_json(directory / 'verification.json', checks)
    before, after = log['baseline'], log['augmented']
    lines = ['# AWS unseen-domain benign expansion diagnostic', '',
        'This is a development diagnostic using the previously inspected v0.2',
        'outer fold 5. It is not a new independent final test. AWS and every other',
        'evaluation apex were excluded from all fitting and inner selection.', '',
        '| Measure | Original v0.2 outer model | Public-benign-expanded model |',
        '|---|---:|---:|',
        f"| AWS FPR | {before['aws']['false_positive_rate']:.6%} | {after['aws']['false_positive_rate']:.6%} |",
        f"| AWS false positives | {before['aws']['fp']:,} | {after['aws']['fp']:,} |",
        f"| All evaluation benign FPR | {before['pooled']['false_positive_rate']:.6%} | {after['pooled']['false_positive_rate']:.6%} |",
        f"| Evaluation attack recall | {before['pooled']['recall']:.6%} | {after['pooled']['recall']:.6%} |",
        f"| Evaluation precision | {before['pooled']['precision']:.6%} | {after['pooled']['precision']:.6%} |",
        f"| Evaluation F1 | {before['pooled']['f1']:.6f} | {after['pooled']['f1']:.6f} |", '',
        f"Evaluation contains {log['evaluation_rows']:,} rows, including {after['aws']['tn']+after['aws']['fp']:,} AWS benign queries.",
        f"Development contains {log['training_rows']:,} rows ({log['training_benign']:,} benign, {log['training_attack']:,} synthetic attacks).", '',
        '## Data and selection', '',
        'Public benign queries are imported from publisher-labelled PCAP prefixes.',
        'The 200,000-packet prefix was chosen before scoring this experiment.',
        'Source labels were retained; no model predictions supplied training labels.',
        'Independent captures receive independent chronological behavioral histories.',
        'The exact ten-feature schema and all shared feature meanings remain unchanged.', '',
        'The same eight RF configurations and three domain-disjoint inner folds',
        'as v0.2 select settings. Threshold selection uses development scores only',
        'with pooled FPR <=1% and each large benign domain FPR <=5%.',
        f"Selected threshold: {log['selection']['decision_threshold']}.",
        f"Selected parameters: `{json.dumps(log['selection']['parameters'], sort_keys=True)}`.", '']
    for source in log['public_inputs']:
        lines.extend([f"- Publisher file: `{source['provenance']['publisher_file']}`.",
            f"- Accepted input queries: {source['imported_rows']:,}; retained for development: {source['retained_rows']:,}; excluded for evaluation-apex overlap: {source['excluded_heldout_domain_rows']:,}.",
            f"- Raw capture SHA256: `{source['provenance']['capture_sha256']}`."])
    lines.extend(['', '## Verification and limits', '',
        'Input/source/artifact hashes, feature order, threshold application, complete',
        'evaluation rows, metric recomputation, exclusion policy and artifact reload',
        'checks passed. Details are in verification.json and experiment.json.', '',
        'The saved model retains the evaluation-domain exclusions. It is a diagnostic',
        'development artifact, not an all-data deployment model. No raw PCAP is',
        'committed. Reproduce the input with the documented public download/import.',
        'Publisher ground truth was not independently relabelled. Independent real',
        'attack captures and untouched benign sources are still required for a final',
        'generalization claim. Inspect recall alongside FPR; reducing false positives',
        'alone does not establish a successful detector.', ''])
    (directory / 'RESULTS.md').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps(checks, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment-dir', type=Path, default=Path('artifacts/aws_benign_expansion_v0.1'))
    summarize(parser.parse_args().experiment_dir)
