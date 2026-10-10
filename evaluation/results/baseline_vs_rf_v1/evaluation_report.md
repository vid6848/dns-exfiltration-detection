# DNS Exfiltration Detection — Model Evaluation and Research Analysis

## 1. Objective

The objective of this evaluation is to compare a statistical threshold-based DNS exfiltration detector with the latest Random Forest classifier developed by the CyberTrace team.

Both detectors are evaluated on the same 45,240 diagnostic records. The analysis covers classification performance, false-positive behaviour, global feature importance, and computational latency.

The evaluation concerns previously inspected diagnostic data containing benign DNS traffic and simulated exfiltration traffic. It is not an independent final test of real-world generalisation.

## 2. Experimental Setup

**Dataset:** `data/processed/cleaned_unified_v0.1.csv`

**Diagnostic population:** 45,240 records, comprising 43,340 benign records and 1,900 simulated exfiltration records.

**Random Forest artifact:** `artifacts/aws_benign_expansion_v0.1/random_forest.joblib`

**Classification threshold:** 0.89

**Behavioural window:** 60 seconds

The Random Forest was evaluated using the saved model artifact and the shared project feature-extraction pipeline. Predictions and attack scores were checked against the saved diagnostic predictions before comparison.

### Statistical baseline

The statistical detector uses four indicators:

- Query length ≥ 52
- Entropy ≥ 4.309101
- Query frequency ≥ 41
- Unique subdomains ≥ 41

A record is flagged as suspicious when at least two indicators meet their respective thresholds.

The baseline thresholds were frozen from the engineering handoff and were not tuned on the diagnostic evaluation records.

## 3. Statistical Baseline vs Random Forest

| Metric | Statistical Baseline | Random Forest |
|---|---:|---:|
| Accuracy | 97.18% | 99.60% |
| Precision | 72.72% | 100.00% |
| Recall | 52.47% | 90.53% |
| F1-score | 0.6096 | 0.9503 |
| False-positive rate | 0.8629% | 0.0000% |
| True positives | 997 | 1,720 |
| True negatives | 42,966 | 43,340 |
| False positives | 374 | 0 |
| False negatives | 903 | 180 |

The Random Forest achieved stronger results than the statistical baseline across the reported classification metrics on this diagnostic population.

Compared with the baseline, the Random Forest detected 723 additional simulated attack records and produced 374 fewer false positives. Its false-negative count decreased from 903 to 180.

These findings indicate that the trained classifier distinguished the evaluated benign and simulated attack records more effectively than the fixed threshold rule. The findings should not be generalised to all real-world DNS exfiltration attacks.

## 4. Confusion Matrix Analysis

### Statistical baseline

| Actual class | Predicted benign | Predicted suspicious |
|---|---:|---:|
| Benign | 42,966 | 374 |
| Simulated exfiltration | 903 | 997 |

The statistical baseline detected 997 of the 1,900 simulated attack records. It incorrectly flagged 374 benign records and missed 903 simulated attacks.

### Random Forest

| Actual class | Predicted benign | Predicted suspicious |
|---|---:|---:|
| Benign | 43,340 | 0 |
| Simulated exfiltration | 180 | 1,720 |

The Random Forest detected 1,720 simulated attacks and missed 180. No false positives were observed among the 43,340 benign diagnostic records.

The zero observed false-positive rate applies only to this evaluation population. It does not establish that the detector will never produce false positives on unseen DNS traffic.

## 5. Random Forest Feature Importance

The latest Random Forest's impurity-based global feature importance values were extracted using the saved model artifact and the exact ten-feature manifest.

| Rank | Feature | Importance |
|---:|---|---:|
| 1 | `entropy` | 38.99% |
| 2 | `subdomain_length` | 17.84% |
| 3 | `query_length` | 14.85% |
| 4 | `digit_ratio` | 9.54% |
| 5 | `longest_label_length` | 8.79% |
| 6 | `special_char_ratio` | 6.13% |
| 7 | `time_interval` | 1.46% |
| 8 | `number_of_labels` | 1.20% |
| 9 | `unique_subdomains` | 0.74% |
| 10 | `query_frequency` | 0.46% |

Entropy was the most influential feature in the saved model, followed by subdomain length and query length.

These values describe global model-level importance. They do not establish causality and do not explain why an individual DNS query received a particular prediction. Correlated features may share or redistribute importance.

## 6. Latency Benchmarking

Latency was measured on a Windows 11 system with Python 3.13.13, NumPy 2.5.3, scikit-learn 1.9.1, and 12 logical CPUs reported by the operating system.

The benchmark used warm-up runs and repeated measurements. The saved model's predictions and scores were checked against the existing diagnostic results before timing was reported.

| Operation | Records per run | Median | p95 |
|---|---:|---:|---:|
| Feature extraction on loaded records | 109,989 | 1.915 s | 1.940 s |
| RF inference | 1 | 8.644 ms | 12.666 ms |
| RF inference | 256 | 11.685 ms | 12.765 ms |
| RF inference | 1,024 | 17.167 ms | 18.693 ms |
| RF inference | 8,192 | 77.290 ms | 81.585 ms |
| RF inference | 45,240 | 367.849 ms | 542.021 ms |
| End-to-end CSV-to-diagnostic predictions | 45,240 predictions from 109,989 source records | 11.207 s | 36.540 s |

The model processed a batch of 45,240 precomputed feature records in a median of approximately 368 milliseconds. Batch inference therefore took substantially less time than the full CSV-to-prediction workflow.

The end-to-end workflow showed considerable variability. Its five measured runs ranged from approximately 10.27 to 40.60 seconds. The p95 estimate is consequently rough and should not be treated as a stable production latency guarantee.

Feature-extraction timing begins with already-loaded records, whereas end-to-end timing includes CSV loading, parsing, feature extraction, selection of diagnostic records, and Random Forest inference. These measurements are not directly interchangeable.

## 7. Research Limitations

1. **Diagnostic evaluation:** The evaluation records were previously inspected during model development. They are not an untouched final test population.

2. **Simulated attacks:** The attack records are synthetic. Performance on these records does not establish equivalent performance against diverse real-world exfiltration techniques.

3. **Generalisation:** Independent benign captures and real attack captures are still required to make stronger generalisation claims.

4. **Observed false positives:** The Random Forest produced zero false positives in this diagnostic dataset, but this result must not be interpreted as a guarantee of zero false positives in deployment.

5. **Recall trade-off:** The expanded Random Forest detects fewer simulated attacks than the earlier model reported in the experiment history. Its reduced false-positive rate must be considered alongside missed attacks.

6. **Feature importance:** Impurity-based importance is model-specific, can be affected by correlated features, and is not a causal explanation.

7. **Latency variability:** The end-to-end benchmark used five measured repetitions. More repetitions and testing on target deployment hardware would be necessary for a robust operational latency estimate.

8. **Experiment provenance:** The experiment summariser previously reported `source_hashes_match = false`, while the other listed checks passed. The mismatch remains unresolved and should be investigated before claiming complete source-provenance verification.

9. **Encrypted DNS:** The current feature-based approach relies on visibility into DNS query content. DNS-over-HTTPS and other encrypted DNS traffic remain outside the core scope of this implementation.

## 8. Conclusion

On the evaluated diagnostic population, the Random Forest outperformed the fixed statistical baseline, improving recall and F1-score while producing fewer false positives. Entropy, subdomain length, and query length were the three most influential global features in the latest saved model.

The batch-inference measurements indicate that the model can classify precomputed DNS feature rows relatively quickly on the tested system. End-to-end processing takes longer because it includes data loading and feature extraction.

The findings support the project's approach of combining interpretable DNS traffic features with a machine-learning classifier. However, independent evaluation on untouched benign sources and real attack captures remains necessary before making stronger claims about practical deployment or generalisation.
