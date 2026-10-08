# Diagnosis of the v0.1 benign-domain failure

The original v0.1 held-out benign set consists of 36,255 records under
`amazonaws.com`, excluded entirely from training and validation. It therefore
tests one benign traffic family, not a representative collection of domains.
The source dataset labels these records benign; their labels were not changed.

Actual feature medians, recomputed with the shared preprocessing/feature APIs:

| Feature | Train benign | Validation benign | AWS test benign | Test attacks |
|---|---:|---:|---:|---:|
| Query length | 27 | 20 | 51 | 52 |
| Subdomain length | 7 | 5 | 37 | 34 |
| Full-query entropy | 3.757 | 2.904 | 4.036 | 4.469 |
| Query count in window | 1 | 5 | 27 | 3 |
| Unique subdomains in window | 1 | 1 | 26 | 3 |

The selected forest's impurity feature importances assign 74.45% in total to
entropy, digit ratio and subdomain length. This is evidence of dependence on
structural patterns in this dataset, not a causal attribution by itself.
Long cloud subdomains overlap attack patterns that were well separated from
the easier training/validation negatives.

Benign validation attack scores range from 0 to 0.2853. Held-out benign AWS
scores have median 0.5655 and 95th percentile 0.68. The median attack score is 1.
For the selected forest, thresholds 0.3 and 0.5 both produce validation F1=1.
The legacy code chooses the first threshold, 0.3, in an exact tie. Validation
therefore failed to distinguish an aggressive threshold from a less aggressive
one. Changing to 0.5 alone would still flag substantial AWS traffic.

The retuned baseline on these same original splits uses count thresholds of 8
for both frequency and unique subdomains, versus medians of 27 and 26 in AWS
benign traffic. Grouping a busy cloud provider as one apex amplifies those
indicators. The forest's behavior is more strongly associated with its structural
features than with those two count features.

The v0.2 workflow therefore adds multi-domain fold coverage, nested grouped
selection, explicit validation FPR targets, conservative threshold tie-breaking,
and stronger regularization. It keeps the ten-feature order and shared feature
semantics unchanged. The old holdout is now diagnostic development data; it
cannot be presented as a fresh independent final test after these changes.
