# Public benign DNS data research and first probe

Research date: 2026-10-08. The goal is to add independent benign environments,
particularly long cloud/CDN names and bursts, rather than dilute AWS errors with
more short ordinary queries. Keep capture/source boundaries as well as apex
boundaries when defining future development and untouched final-test data.

## Sources checked

| Source | Published content | Access and fit |
|---|---|---|
| [Daumel DNS exfiltration dataset](https://github.com/Daumel/dns-exfiltration-dataset), [Kaggle distribution](https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset) | Author reports 797,626 benign and 785,537 malicious query-response pairs; raw PCAPs include university traffic and top-domain traffic. CSV has 45 fields including names, IPs, timestamps and labels. | Kaggle metadata lists CC BY 4.0. Individual files were accessible without registration. Full distribution is about 34.55 GB; benign CSV is 869,915,981 bytes. Small top-domain captures permit an inexpensive first check. University captures are hundreds of MB to about 1 GB each. |
| [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html) | Publisher reports 641,642 benign records and offers PCAP and structured features. Benign generation uses HTTP requests to Alexa top domains. | [Download page](https://cicresearch.ca/CICDataset/CICBellEXFDNS2021/) asks for contact and organization details; none were submitted. Attribution to the dataset/paper is required. Recompute our features from raw events rather than treating its 30 features as compatible. |

Daumel is the practical next source. Its university subset is more relevant to
workload diversity than repeatedly extending the top-domain list. Neither
publisher description guarantees sufficient examples of the specific internal
AWS search-suffix behavior that failed here; inspect that coverage explicitly.
The metadata was checked using Kaggle's dataset view and file-list endpoints:

```text
https://www.kaggle.com/api/v1/datasets/view/daumel/dns-tunneling-dataset
https://www.kaggle.com/api/v1/datasets/list/daumel/dns-tunneling-dataset?pageSize=200
```

Retain attribution to Daumel and the upstream captures identified in its README.
Do not assume the packaging license removes upstream provenance obligations.

## Small independent benign probe

Downloaded only this 3,635,504-byte file, not the full dataset:

```text
dns-exfiltration-dataset/01_original_pcap_files/benign/top_1_million_domains/normal_00000_20230805150331.pcap
```

The v0.2 model and threshold 0.83 were fixed before evaluating the sample. No
training or threshold selection used these scores. Shared normalization,
chronological feature extraction, the exact ten-feature order and a fresh
60-second history were used. Label 0 comes from the publisher's benign directory;
it is not independently verified ground truth.

| Population | Queries | False positives | FPR |
|---|---:|---:|---:|
| All supported benign queries | 15,000 | 6 | 0.0400% |
| Apex domains absent from all current development data | 14,745 | 6 | 0.04069% |

The capture has 30,000 packets: 15,000 queries and 15,000 non-query packets.
No queries were rejected or deduplicated. There are 13,603 apex domains, of
which 13,576 are absent from development. The inference model hash, input hash,
feature order, probability quantiles and false-positive examples are saved in
`artifacts/public_benign_probe/experiment.json`. Raw packets remain local and are
ignored by Git.

This is a small benign-only probe, not an overall accuracy or attack-recall test.
It does not overturn the nested AWS-domain FPR of 99.83%. Many ordinary short
queries can pass while cloud workloads still fail. The capture boundary may
truncate earlier behavioral history. The reader supports UDP, single-question
DNS and does not reassemble TCP streams or IP fragments.

The sample's scores have now been inspected. Preserve it as a disclosed benchmark;
do not call it an untouched test after using its results to guide changes.

## Repeat the probe

From the repository root, install the optional reader in the project environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
```

The single-file public download URL is the following prefix plus the URL-encoded
publisher path above:

```text
https://www.kaggle.com/api/v1/datasets/download/daumel/dns-tunneling-dataset/
```

After downloading that file locally:

```powershell
.\.venv\Scripts\python.exe -m scripts.probe_public_benign --pcap .public-data-research/benign_sample_download
```

Use `--publisher-file` to record a different Daumel benign file accurately, and
`--output` to keep each capture's report separate. The script reads packets only;
it sends no network traffic and does not fit a model.

## Data expansion protocol

1. Acquire complete labelled university benign captures from Daumel. Inventory
   query length, entropy, subdomain count, frequency and unique-subdomain tails,
   including cloud/CDN coverage, before allocating captures.
2. Convert only query events to the canonical raw fields. For CSV, explicitly map
   `dns_domain_name` to `requested_server_name` and `Benign` to 0. Do not pass
   publisher-derived feature columns to the forest. Query-response rows may omit
   unanswered requests, which matters for behavioral counts; PCAP is preferred.
3. Predeclare capture/source-based development and test allocations. Remove apex
   and duplicate-event overlap for an unseen-domain claim. Keep complete
   `(src_ip, apex_domain)` histories together and compute features inside each
   allocated partition. Reserve the final source/captures without inspecting
   model scores. Do not mix independent sources by random row splitting.
4. Use expanded development data for selection and refitting. Evaluate the
   untouched final capture set once, with per-source and per-domain FPR as well
   as overall metrics. A benign-only final capture cannot establish attack
   recall; that needs independent attack captures as well.

No larger capture has been downloaded or added to training in this experiment.
