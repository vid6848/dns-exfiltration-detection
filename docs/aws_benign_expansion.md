# AWS benign expansion experiment

The v0.2 forest flagged 36,193 of 36,255 unseen AWS benign queries. The next
development experiment adds independent, publisher-labelled university benign
traffic while preserving the ten-feature contract. No cloud-domain whitelist,
label changes, new features or AWS-specific inference exception is used.

## Data provenance

Source: [Daumel DNS exfiltration dataset](https://github.com/Daumel/dns-exfiltration-dataset),
distributed on [Kaggle](https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset)
with CC BY 4.0 listed in the distribution metadata. Credit Daumel and the upstream
Singh et al. university captures described in the author's README. Labels come
from the publisher's benign directory and are not independently verified.

Publisher path:

```text
dns-exfiltration-dataset/01_original_pcap_files/benign/university_traffic/monday/20160425_075435.pcap
```

The complete downloaded PCAP is 253,103,755 bytes. SHA256:

```text
508668addd6528925586b22e948aa545cb718712907b7da6e17609d90d56c2bb
```

Import takes the first 200,000 packets in capture order. This limit was chosen
before evaluating model scores. It is a contiguous prefix, not a random sample,
so inter-arrival windows within the prefix remain intact. History starts fresh
at the beginning; earlier packets outside this file are unavailable.

Of the 200,000 packets, 89,130 are DNS query packets. Shared validation rejects
942 invalid records, and the reader excludes 49 queries with unsupported
question/network structure. The resulting CSV contains 88,139 query events,
3,123 apex domains and a time span of about 711 seconds. Non-query packets are
excluded, as are unsupported TCP queries. There is no fragment reassembly.

Canonical CSV SHA256:

```text
eb10aa8d9db17d3a70d61614f0ab74f30d4a29b8de5bda342e22e199de8021fe
```

## Evaluation and leakage controls

- Freeze the existing v0.2 outer fold 5 as the diagnostic evaluation population.
  Preserve its original row IDs, labels and domain assignment. Its AWS errors
  have already been inspected; this is development evaluation, not a fresh test.
- Exclude every evaluation apex, including all `amazonaws.com` queries, from
  both original development data and every imported public capture.
- Compute causal features independently for each capture, in timestamp order.
  Equal private IP addresses in separate networks cannot share behavioral
  history. Within a capture, behavior still groups on `(src_ip, apex_domain)`.
- Use the same eight fixed RF configurations and three domain-disjoint inner
  folds as v0.2. Select thresholds using development scores only, under pooled
  FPR <=1% and large-domain FPR <=5%. No evaluation scores enter selection.
- Fit the selected estimator on development data, then score the frozen
  evaluation once. Compare with saved v0.2 outer predictions on exactly the
  same records. Report attack recall and per-domain FPR alongside AWS FPR.

The saved model preserves the evaluation-domain exclusions. It is intended for
this diagnostic, not for deployment. The model's ten ordered inputs remain:

```text
query_length, longest_label_length, number_of_labels, entropy, digit_ratio,
special_char_ratio, subdomain_length, query_frequency, unique_subdomains,
time_interval
```

## Reproduce

Use Python 3.12 and the pinned training/dev dependencies plus
`requirements-data.txt`. From the repository root:

The exact accepted CSV and provenance sidecar are included as a 1.23 MB gzip
archive with the experiment, so the large PCAP download is optional. Restore to
a new local path, then run selection and verification:

```powershell
.\.venv\Scripts\python.exe -m scripts.restore_public_benign --output .public-data-research/university_restored.csv
.\.venv\Scripts\python.exe -m src.ml.aws_generalization --benign .public-data-research/university_restored.csv --output-dir artifacts/aws_benign_expansion_repeat --n-jobs 2
.\.venv\Scripts\python.exe -m scripts.summarize_aws_expansion --experiment-dir artifacts/aws_benign_expansion_repeat
```

Alternatively, rebuild that input from the original capture:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -r requirements-data.txt
New-Item -ItemType Directory -Path .public-data-research -Force
$taskPublisherPath = 'dns-exfiltration-dataset/01_original_pcap_files/benign/university_traffic/monday/20160425_075435.pcap'
$taskDownloadUrl = 'https://www.kaggle.com/api/v1/datasets/download/daumel/dns-tunneling-dataset/' + [uri]::EscapeDataString($taskPublisherPath)
Invoke-WebRequest -Uri $taskDownloadUrl -OutFile .public-data-research/university_monday.pcap
.\.venv\Scripts\python.exe -m scripts.import_public_benign --pcap .public-data-research/university_monday.pcap --output .public-data-research/university_monday.csv --publisher-file $taskPublisherPath --max-packets 200000
.\.venv\Scripts\python.exe -m src.ml.aws_generalization --benign .public-data-research/university_monday.csv --output-dir artifacts/aws_benign_expansion_repeat --n-jobs 2
.\.venv\Scripts\python.exe -m scripts.summarize_aws_expansion --experiment-dir artifacts/aws_benign_expansion_repeat
```

Importer and trainer output paths must be new/empty to preserve evidence. Check
the raw and CSV hashes against those above. The importer writes a provenance
sidecar; training verifies that hash before accepting the public input. Duplicate
imports of the same capture are rejected. Raw PCAP and local CSV stay outside Git.

Committed results are in `artifacts/aws_benign_expansion_v0.1/RESULTS.md`;
`experiment.json` records every selection trial, per-domain errors, public-data
feature quantiles, input/source/model hashes and package versions. The saved
bundle can be read with the existing `load_model` and `predict_features` APIs.

An independent benign source and real attack capture are still needed for final
evaluation. Publisher-labelled university traffic may not cover the specific
AWS internal search-suffix workload, so success cannot be assumed from merely
adding more rows. Do not choose a threshold by scanning AWS evaluation scores.
