# CyberTrace Stage 1 & 2 Handoff: Preprocessing & Parsing Specification

**Author/Owner:** Yash (Preprocessing & Parsing)  
**Project:** DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)  
**Downstream Consumers:** Hero (Per-Query Features), Rudraksh (Behavioral Features & Baseline), Jaynish (Random Forest Training), Pranay (FastAPI Inference)

---

## 1. CRITICAL ARCHITECTURAL WARNING: DATA LEAKAGE PREVENTION

> [!WARNING]
> ### STRICT CONTRACT DIRECTIVE:
> **`src_ip`**, **`dst_ip`**, **`timestamp`** (raw datetime or epoch), **`requested_server_name`** (raw FQDN), and **`source`** **MUST NOT BE USED DIRECTLY AS ML FEATURES.**

### Why This Is Forbidden:
1. **`src_ip` (Source IP):**
   - *Risk:* 99.99% of raw benign traffic originated from `10.0.30.186`. If the ML model trains on `src_ip`, it simply memorizes host addresses rather than learning the structural anatomy of DNS exfiltration.
   - *Allowed Use:* **Grouping key only** for Rudraksh to aggregate sliding-window behaviors per client.
2. **`dst_ip` (Destination Resolver IP):**
   - *Risk:* Resolvers (`8.8.8.8`, `1.1.1.1`, `10.0.0.2`) are static infrastructure endpoints. Models will memorize resolvers rather than query payload patterns.
   - *Allowed Use:* Infrastructure routing metadata only; excluded from model inputs.
3. **`timestamp` / `epoch_time` (Raw Temporal Values):**
   - *Risk:* Datetime strings or monotonic epochs create artificial chronological splits because benign and attack datasets were captured at specific dates and times.
   - *Allowed Use:* **Chronological ordering** and computing relative time intervals ($\Delta t = t_i - t_{i-1}$) or time-window boundaries ($t \in [T, T + W]$).
4. **`requested_server_name` (Raw Domain String):**
   - *Risk:* Feeding raw domain names or high-cardinality categorical hashes teaches the classifier to memorize specific attacker apex domains (e.g., `tunnel-sync.net`, `data-relay.info`, `exfil-corp.org`).
   - *Allowed Use:* Hero decomposes the string into structural numeric features (`query_length`, `entropy`, `digit_ratio`), and Rudraksh groups by `apex_domain` to compute unique subdomain counts.
5. **`source` (Provenance Tag):**
   - *Risk:* Tagging rows with `"Mendeley..."` vs `"CyberTrace Synthetic..."` represents **100% target label leakage**.
   - *Allowed Use:* Dataset auditability and documentation only. Must be stripped before feature matrices are built.

*Enforcement:* The preprocessing module provides `verify_ml_feature_safety(feature_list)` in `src/preprocessing/schema.py` which will automatically raise a `DataLeakageError` if any of these columns are included in a proposed ML feature set.

---

## 2. Preprocessed Record Schema (Handoff to Hero & Rudraksh)

The preprocessed output provides normalized, validated, and decomposed records:

| Field Name | Type | Category | Description | Primary Consumer |
|---|---|---|---|---|
| `timestamp` | string | Temporal Anchor | Standardized UTC format: `YYYY-MM-DD HH:MM:SS.mmm` | Rudraksh (Ordering) |
| `epoch_time` | float | Temporal Anchor | UTC epoch seconds for calculating $\Delta t$ and sliding window math | Rudraksh ($\Delta t$ intervals) |
| `src_ip` | string | Grouping Key | Client IP address originating the query | Rudraksh (Client group) |
| `dst_ip` | string | Metadata | Destination resolver IP | System Logging |
| `requested_server_name` | string | Normalized Domain | Fully Qualified Domain Name (lowercase, no trailing dots, RFC compliant) | Hero (Entropy/Ratios) |
| `apex_domain` | string | Grouping Key | Registered apex domain (eTLD+1, e.g., `data-relay.info`, `example.com`) | Rudraksh (Domain group) |
| `subdomain` | string | Structural Component | Subdomain portion excluding apex domain (e.g., `s.chunk1.chunk2`) | Hero |
| `tld` | string | Structural Component | Top-Level Domain (e.g., `info`, `com`, `co.uk`, `internal`) | Hero |
| `label_count` | integer | Pre-parsed Metric | Count of dot-separated labels | Hero |
| `longest_label` | string | Pre-parsed Component | String of the longest label | Hero |
| `longest_label_length` | integer | Pre-parsed Metric | Character length of the longest label | Hero |
| `subdomain_length` | integer | Pre-parsed Metric | Total character length of subdomain portion | Hero |
| `query_type` | string | Metadata | DNS query type (e.g., `A`, `AAAA`) | Feature pipelines |
| `label` | integer | Target Ground Truth | `0` = Benign, `1` = Simulated Exfiltration | Jaynish (Model training) |
| `source` | string | Audit Metadata | Provenance description | Excluded from ML |

---

## 3. How to Consume the Preprocessed Module

### Python API
```python
from src.preprocessing import PreprocessingPipeline, verify_ml_feature_safety

pipeline = PreprocessingPipeline(check_duplicates=True)

# 1. Process individual raw rows (e.g. inside FastAPI /predict endpoint)
raw_record = pipeline.parse_csv_row_to_raw_record({
    "timestamp": "2025-06-13 09:31:25.564",
    "src_ip": "10.0.30.186",
    "dst_ip": "8.8.8.8",
    "requested_server_name": "s.a1b2c3d4.tunnel-sync.net.",
    "label": 1
})
normalized = pipeline.normalize_and_parse_record(raw_record)
print(normalized.apex_domain)       # "tunnel-sync.net"
print(normalized.subdomain)         # "s.a1b2c3d4"
print(normalized.longest_label)     # "tunnel-sync"
print(normalized.epoch_time)        # 1749807085.564

# 2. Safety check before feeding feature names to Random Forest
proposed_features = [
    "query_length", "entropy", "label_count",
    "digit_ratio", "longest_label_length"
]
verify_ml_feature_safety(proposed_features)  # Passes cleanly!
```

### CLI Command to Generate Cleaned Combined Dataset
```bash
python3 -m src.preprocessing.pipeline \
  --benign data/processed/benign_dns_v0.1.csv \
  --synthetic data/processed/synthetic_exfiltration_v0.1.csv \
  --output data/processed/cleaned_unified_v0.1.csv
```
