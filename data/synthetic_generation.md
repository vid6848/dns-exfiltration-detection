# Synthetic DNS Exfiltration Dataset Specification

## 1. Purpose & Overview

This document specifies the architecture, generation methodology, and scientific rationale for the **Simulated Attack Dataset** component of the academic research project **"DNS Exfiltration Detection Using Network Traffic Analysis"** (CE305/CS305, CyberTrace team).

The synthetic dataset provides controlled, varied, and reproducible DNS-exfiltration-like traffic (`label = 1`) designed to be combined with the validated baseline benign dataset (`data/processed/benign_dns_v0.1.csv`, `label = 0`) for feature evaluation, baseline statistical benchmarking, and supervised machine learning (Random Forest).

> **Academic & Ethical Disclaimer:**  
> This dataset contains purely synthetic, randomly generated, and non-sensitive token payloads designed to simulate observable structural and temporal characteristics of DNS tunneling. It does **not** contain real confidential data, real exfiltrated payloads, active malware communications, or exploit code.

---

## 2. Why Synthetic Traffic Is Needed

An audit of the raw Mendeley dataset (`data/raw/dataset_dns_exfiltration.csv`) revealed severe limitations that necessitate a controlled synthetic generator:

1. **Host-Level Labelling Artifacts (Label Noise):**
   - In the raw Mendeley dataset, 74.8% (7,000 / 9,364) of records marked as `label = 1` originated from a single host (`10.0.30.164`) querying routine system and cloud services:
     - `ssm.sa-east-1.amazonaws.com` (4,086 rows)
     - `api.snapcraft.io` (428 rows)
     - `connectivity-check.ubuntu.com` (413 rows)
     - `motd.ubuntu.com` (202 rows)
   - These normal system queries were labeled as attack traffic simply because the entire host was tagged as infected, which would teach ML models spurious correlations rather than true exfiltration detection.
2. **Temporal Disconnection:**
   - The raw benign data was collected on **June 13–14, 2025**, whereas the raw attack data was recorded months later (**August–October 2025**). Any model utilizing timestamps or inter-arrival windows on raw data would suffer from chronological data leakage.
3. **Limited Tool Diversity:**
   - Real exfiltration attacks employ a wide spectrum of encodings, label depths, and exfiltration cadences (e.g., base32, hex, variable-length chunks, low-and-slow drip vs. high-throughput bursts). The raw dataset captured only a narrow sample of `dnscat` traffic.
4. **Reproducibility:**
   - A parameterized synthetic generator allows repeatable experiments under controlled class balances and known ground-truth behaviors.

---

## 3. Data Contract & Schema

The synthetic dataset strictly conforms to the exact 10-column schema established in `data/processed/benign_dns_v0.1.csv`:

| Column Name | Type | Description |
|---|---|---|
| `timestamp` | string (datetime) | Flow timestamp formatted as `YYYY-MM-DD HH:MM:SS.mmm` |
| `src_ip` | string | Source IP address originating the DNS request |
| `dst_ip` | string | Destination DNS resolver IP address |
| `requested_server_name` | string | Fully Qualified Domain Name (FQDN) queried |
| `dns_query_length` | integer | Total character length: `len(requested_server_name)` |
| `dns_query_entropy` | float | Shannon entropy (base 2) calculated over complete FQDN |
| `dns_subdomain_count` | integer | Total dot-delimited label count: `len(requested_server_name.split('.'))` |
| `dns_numerical_ratio` | float | Digit ratio: `count(digits) / len(requested_server_name)` |
| `label` | integer | Constant integer: `1` (DNS Exfiltration) |
| `source` | string | Dataset provenance tag: `"CyberTrace Synthetic DNS Exfiltration v0.1"` |

---

## 4. Attack Profiles Implemented

To avoid naive, trivially separable patterns, the generator implements multiple structural and temporal profiles:

### Structural & Encoding Profiles

1. **Profile A — Encoded-Looking Chunked Subdomains (`profile_a_chunked_b64`):**
   - Emulates multi-stage Base64-like / alphanumeric encoded chunking across multiple subdomain labels (e.g., `<chunk1>.<chunk2>.<session>.<domain>`).
   - Produces high entropy (~3.9–4.3) and variable label lengths.
2. **Profile B — Hexadecimal-Like Payload Chunks (`profile_b_hex`):**
   - Emulates hex-based DNS tunneling protocols (such as `dnscat2` and `iodine` in hex mode).
   - Generates hex strings (`0-9a-f`) with session prefixes and sequence counters (e.g., `dnscat.<hex32>.<domain>`).
   - Produces higher numerical ratios (~0.25–0.45) and moderate entropy (~3.5–3.95).
3. **Profile C — Base32-Like Payload Chunks (`profile_c_base32`):**
   - Emulates RFC 4648 Base32 payloads (`a-z2-7`), standard in DNS covert channels due to DNS case-insensitivity.
   - Balances entropy (~3.8–4.2) and numerical ratio (~0.10–0.25).
4. **Profile D — Variable-Length Payload Chunks (`profile_d_variable_length`):**
   - Intentionally generates short (6–18 char) to medium (20–48 char) payloads.
   - Prevents the trivial assumption that "all attack queries are maximal length" by deliberately creating overlap with benign query lengths.
5. **Profile G — Multiple Subdomain Structures (`profile_g_multi_structure`):**
   - Varies label depth across 4, 5, 6, and 7 labels (e.g., `<seq>.<chunk1>.<chunk2>.<session>.<domain>`).
   - Overlaps naturally with the benign dataset's label count distribution (benign range: 2–8, median: 5).

### Temporal Transmission Modes

6. **Profile E — Low-and-Slow DNS Activity (`timing_low_and_slow`):**
   - Simulates stealthy drip exfiltration with wide query inter-arrival times (15 to 300 seconds between successive queries).
   - Designed to mimic evasion of simple threshold-based rate detectors.
7. **Profile F — High-Frequency / Burst DNS Activity (`timing_burst`):**
   - Simulates automated bulk data dumping with rapid query bursts (50 ms to 1.5 s inter-arrival times).

---

## 5. Mitigation of Data Leakage & Trivial Separability

| Potential Shortcut / Leak | Problem | Generator Mitigation Strategy |
|---|---|---|
| **Timestamp Separation** | Benign is June 2025; raw attacks were August–October 2025. | Attack timestamps are constrained and interleaved strictly within the benign timeline (`2025-06-13 09:31:25` to `2025-06-14 09:01:06`). |
| **Source IP Memorization** | Benign traffic is 99.99% from `10.0.30.186`. If attacks use only other IPs, ML learns IP filter. | 50% of synthetic attacks are generated from `10.0.30.186` (simulating compromised primary host), alongside other private IPs (`10.0.30.164`, `10.0.30.100`, etc.). |
| **Apex Domain Memorization** | Using a single attacker domain (e.g. `attack.com`) leads to domain token memorization. | Uses a configurable pool of 10+ distinct synthetic base domains across diverse TLDs (`.org`, `.net`, `.com`, `.io`, `.info`, `.biz`, `.xyz`, etc.). |
| **Resolver Uniformity** | Single hard-coded resolver creates trivial destination correlation. | Configurable pool of public and internal resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `10.0.0.2`). |
| **Feature Formula Drift** | Inconsistent entropy or label calculation corrupts feature space. | Replicates exact mathematical definitions used in `benign_dns_v0.1.csv` calculated over the entire FQDN. |

---

## 6. Exact Feature Calculation Formulas

In conformance with the existing benign dataset:

1. **`dns_query_length`:**
   $$\text{length} = \operatorname{len}(\text{requested\_server\_name})$$
2. **`dns_query_entropy`:**
   $$H = -\sum_{c \in \Sigma} p(c) \log_2 p(c)$$
   Calculated across all characters in the complete `requested_server_name` string (including dots and hyphens).
3. **`dns_subdomain_count`:**
   $$\text{labels} = \operatorname{len}(\text{requested\_server\_name.split}('.'))$$
4. **`dns_numerical_ratio`:**
   $$\text{ratio} = \frac{\sum_{c} \mathbb{I}(c \in [0-9])}{\operatorname{len}(\text{requested\_server\_name})}$$

---

## 7. Configuration & CLI Usage

Generator script: [data/generate_synthetic_exfiltration.py](file:///c:/Users/ADMIN/OneDrive/Desktop/dns/dns-exfiltration-detection/data/generate_synthetic_exfiltration.py)

```bash
python data/generate_synthetic_exfiltration.py \
  --num-records 10000 \
  --seed 42 \
  --output data/processed/synthetic_exfiltration_v0.1.csv \
  --start-time "2025-06-13 09:31:25.666" \
  --end-time "2025-06-14 09:01:06.636"
```

### Validator Script

Validator script: [data/validate_synthetic.py](file:///c:/Users/ADMIN/OneDrive/Desktop/dns/dns-exfiltration-detection/data/validate_synthetic.py)

```bash
python data/validate_synthetic.py \
  --target data/processed/synthetic_exfiltration_v0.1.csv \
  --expected-rows 10000
```

---

## 8. Limitations

1. **Simulated Payloads:** Payloads are pseudo-randomly generated tokens; no real covert protocol handshake is conducted over live sockets.
2. **Static Apex Pool:** Although multiple base domains are used, real-world attackers may use newly registered domains (NRDs) or dynamic DNS services.
3. **Feature Scope:** Features reflect the 10-column schema of `benign_dns_v0.1.csv`. Extended contextual window features (e.g. query rate per minute per domain) must be computed in subsequent feature engineering stages.
