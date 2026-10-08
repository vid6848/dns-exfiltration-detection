# AWS unseen-domain benign expansion diagnostic

This is a development diagnostic using the previously inspected v0.2
outer fold 5. It is not a new independent final test. AWS and every other
evaluation apex were excluded from all fitting and inner selection.

| Measure | Original v0.2 outer model | Public-benign-expanded model |
|---|---:|---:|
| AWS FPR | 99.828989% | 0.000000% |
| AWS false positives | 36,193 | 0 |
| All evaluation benign FPR | 83.544070% | 0.000000% |
| Evaluation attack recall | 99.736842% | 90.526316% |
| Evaluation precision | 4.973362% | 100.000000% |
| Evaluation F1 | 0.094743 | 0.950276 |

Evaluation contains 45,240 rows, including 36,255 AWS benign queries.
Development contains 150,353 rows (142,253 benign, 8,100 synthetic attacks).

## Data and selection

Public benign queries are imported from publisher-labelled PCAP prefixes.
The 200,000-packet prefix was chosen before scoring this experiment.
Source labels were retained; no model predictions supplied training labels.
Independent captures receive independent chronological behavioral histories.
The exact ten-feature schema and all shared feature meanings remain unchanged.

The same eight RF configurations and three domain-disjoint inner folds
as v0.2 select settings. Threshold selection uses development scores only
with pooled FPR <=1% and each large benign domain FPR <=5%.
Selected threshold: 0.89.
Selected parameters: `{"class_weight": null, "max_depth": 12, "max_features": "sqrt", "min_samples_leaf": 5, "n_estimators": 150, "n_jobs": 2, "random_state": 42}`.

- Publisher file: `dns-exfiltration-dataset/01_original_pcap_files/benign/university_traffic/monday/20160425_075435.pcap`.
- Accepted input queries: 88,139; retained for development: 85,604; excluded for evaluation-apex overlap: 2,535.
- Raw capture SHA256: `508668addd6528925586b22e948aa545cb718712907b7da6e17609d90d56c2bb`.

## Verification and limits

Input/source/artifact hashes, feature order, threshold application, complete
evaluation rows, metric recomputation, exclusion policy and artifact reload
checks passed. Details are in verification.json and experiment.json.

The saved model retains the evaluation-domain exclusions. It is a diagnostic
development artifact, not an all-data deployment model. No raw PCAP is
committed. Restore the included CSV archive or repeat the documented
public download/import to reproduce the development input.
Publisher ground truth was not independently relabelled. Independent real
attack captures and untouched benign sources are still required for a final
generalization claim. Inspect recall alongside FPR; reducing false positives
alone does not establish a successful detector.
