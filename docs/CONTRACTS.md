# CyberTrace Data & API Architecture Contracts

**Author:** Soham (Project Coordination & Integration, `soham.prajapati24@spit.ac.in`)  
**Version:** 1.0.0  
**Status:** Authoritative  
**Date:** 2026-10-13  
**Implementation Modules:** `api/main.py`, `src/preprocessing/`, `src/features/`, `frontend/src/api/client.js`  

---

## 1. Scope and Authority

This document defines the binding technical contracts across the CyberTrace system:
1. Ingestion format and request field schemas.
2. Timezone policy and timestamp handling.
3. Machine learning feature contracts (ordering, boundaries, and leakage prohibition).
4. Prediction outputs, terminology (`attack_score` vs `confidence`), thresholds, and risk labels.
5. Error response JSON schema and HTTP status codes.
6. Invalid-row handling, size/row limits for CSV ingestion.
7. Capture isolation semantics.
8. State persistence policies for alerts and traffic statistics.

---

## 2. Ingestion & Request Schemas

### 2.1 Single Query Request Schema (`DNSQuery`)

Used by `POST /predict`.

| Field Name | Type | Required | Default | Validation & Semantics |
|---|---|---|---|---|
| `timestamp` | `string` | Yes | - | ISO-8601 or `YYYY-MM-DD HH:MM:SS.mmm`. Parsed to UTC. |
| `src_ip` | `string` | Yes | - | Valid IPv4 or IPv6 client address. Used strictly for grouping. |
| `dst_ip` | `string` | Yes | - | Valid IPv4 or IPv6 resolver address. System routing metadata. |
| `requested_server_name` | `string` | Yes | - | Fully Qualified Domain Name (FQDN). Capped at RFC 1035 max (253 chars). |
| `query_type` | `string` | No | `"A"` | DNS record type (e.g., `A`, `AAAA`, `TXT`). |
| `source` | `string` | No | `"CyberTrace API"` | Provenance identifier. Excluded from ML features. |
| `capture_id` | `string` | No | `"default"` | Logical capture grouping identifier. Isolates behavioral state. |

### 2.2 Batch Query Request Schema (`BatchDNSQuery`)

Used by `POST /analyze`.

| Field Name | Type | Required | Limits | Description |
|---|---|---|---|---|
| `queries` | `List[DNSQuery]` | Yes | Min: 1, Max: 1,000 | Ordered array of DNS query events to evaluate. |

### 2.3 CSV Batch Ingestion Contract (`POST /analyze/csv`)

- **Format:** Multipart form upload (`file: UploadFile`) with optional form field `capture_id: str`.
- **Allowed MIME types:** `text/csv`, `text/plain`, `application/vnd.ms-excel`, or `.csv` extension.
- **Maximum file size:** 15 Megabytes.
- **Maximum row limit:** 20,000 queries per upload.
- **Header requirements:** Required columns in any order:
  - `timestamp`
  - `src_ip`
  - `dst_ip`
  - `requested_server_name` (or `query` / `domain` as acceptable aliases)
  - Optional: `query_type` (defaults to `"A"`), `capture_id` (defaults to filename or form parameter).

---

### 2.4 Streaming Ingestion Contract (`POST /ingest`)

Used by continuous sensors (`scripts/dns_sensor.py`, the browser extension).

| Field Name | Type | Required | Limits | Description |
|---|---|---|---|---|
| `capture_id` | `string` | Yes | 1–128 chars | Sensor identity. Behavioral history for this capture persists across requests (bounded LRU of 256 captures). |
| `queries` | `List[DNSQuery]` | Yes | Min: 1, Max: 1,000 | Events in any order; sorted chronologically before feature extraction. |

Response: `{capture_id, accepted, rejected, suspicious_queries, alerts: [{alert_id, requested_server_name, src_ip, attack_score, risk_label}], errors}`. A record that is invalid, or older than the capture's last event for the same `(src_ip, apex_domain)` group, is counted in `rejected` and does not fail the batch.

## 3. Timezone & Missing Timestamp Policy

1. **Timezone:** All timestamps are parsed to UTC. If a timestamp string contains explicit timezone offsets (e.g., `+05:30` or `Z`), it is normalized to UTC epoch seconds. If naive, UTC is assumed.
2. **Missing Timestamps:**
   - In `/predict`: `timestamp` is strictly required; missing or empty timestamp raises HTTP 422.
   - In `/analyze/csv`: Rows with completely missing or unparseable timestamps fallback to either the timestamp of the immediately preceding valid row or the server ingestion timestamp, logging an invalid timestamp warning.
3. **Chronological Sorting:**
   - Batches and CSV uploads are sorted chronologically by `epoch_time` before behavioral feature extraction, guaranteeing proper sliding-window progression. The response preserves the client's original row order.

---

## 4. Machine Learning Feature Contract

### 4.1 Strict Leakage Prevention Policy
Per `src/preprocessing/schema.py:verify_ml_feature_safety`, the following metadata fields **MUST NEVER** be included in the feature vector passed to `predict_features()`:
- `src_ip`
- `dst_ip`
- `timestamp` / `epoch_time`
- `requested_server_name` / `apex_domain` / `subdomain` / `labels`
- `source`
- `label`

### 4.2 Exact Ten-Feature Order & Schema
The inference bundle `artifacts/aws_benign_expansion_v0.1/random_forest.joblib` requires exactly 10 features in this sequence:

| Index | Feature Name | Type | Source Module | Definition & Boundaries |
|---|---|---|---|---|
| 0 | `query_length` | `int` | `src.features.per_query` | Total length of FQDN in characters ($\ge 1$). |
| 1 | `longest_label_length` | `int` | `src.features.per_query` | Length of longest dot-delimited label ($\le 63$). |
| 2 | `number_of_labels` | `int` | `src.features.per_query` | Count of dot-delimited segments ($\ge 1$). |
| 3 | `entropy` | `float` | `src.features.per_query` | Shannon entropy over the full FQDN: $-\sum p_i \log_2(p_i)$. |
| 4 | `digit_ratio` | `float` | `src.features.per_query` | Ratio of numeric digits: $\text{count}(\text{digits}) / \text{query\_length}$. |
| 5 | `special_char_ratio` | `float` | `src.features.per_query` | Ratio of non-alphanumeric chars: $\text{count}(\text{not isalnum()}) / \text{query\_length}$. |
| 6 | `subdomain_length` | `int` | `src.features.per_query` | Total character count of subdomain prefix excluding apex. |
| 7 | `query_frequency` | `float` | `src.features.behavioral` | Queries to same `(src_ip, apex_domain)` in $[t - 60.0, t]$. |
| 8 | `unique_subdomains` | `float` | `src.features.behavioral` | Distinct subdomains for `(src_ip, apex_domain)` in $[t - 60.0, t]$. |
| 9 | `time_interval` | `float` | `src.features.behavioral` | Seconds since previous query for same `(src_ip, apex_domain)`. **Set to `-1.0` for first query**. |

---

## 5. Inference, Prediction & Terminology Contracts

### 5.1 Calibrated Operating Threshold
- **Threshold ($\tau$):** **`0.89`**.
- **Model Bundle Execution:** Inference is executed strictly via:
  ```python
  from src.ml.artifact import load_model, predict_features
  bundle = load_model(MODEL_PATH)
  predictions, attack_scores = predict_features(bundle, feature_rows)
  ```
  `bundle["model"].predict()` must never be called directly because it defaults to $\tau = 0.50$, violating the calibrated operating policy.

### 5.2 Terminology Policy
- **Attack Score (`attack_score`):** The float returned by the model representing tree vote fraction for class 1.
- **Forbidden Term:** **Never label this "confidence" or "calibrated confidence"**; probability calibration has not been formally established across unknown network distributions.

### 5.3 Response Fields Schema

```json
{
  "alert_id": "alt_01HXYZ...",
  "prediction": "suspicious",
  "label": 1,
  "attack_score": 0.942,
  "threshold": 0.89,
  "risk_label": "CRITICAL",
  "rule_indicators": {
    "query_length_flag": true,
    "entropy_flag": true,
    "query_frequency_flag": false,
    "unique_subdomains_flag": false,
    "agreeing_indicators_count": 2,
    "baseline_flagged": true
  },
  "model_identity": {
    "artifact": "artifacts/aws_benign_expansion_v0.1/random_forest.joblib",
    "trees": 150,
    "features": 10,
    "deployment_ready": false,
    "diagnostic_label": "Diagnostic Development Evaluation (Outer Fold 5)"
  }
}
```

The `rule_indicators` map directly derives from the frozen 4-indicator statistical baseline (`src/baseline/detector.py`):
- `query_length >= 52.0`
- `entropy >= 4.309101`
- `query_frequency >= 41.0`
- `unique_subdomains >= 41.0`
- `baseline_flagged`: `True` when $\ge 2$ indicators cross their thresholds simultaneously.

### 5.4 Risk Label Classification
The risk tier classification is designed to never contradict the binary prediction decision:
- **Benign Tiers (`attack_score < threshold`, prediction = `benign`):**
  - `LOW`: `attack_score < 0.50` (routine benign traffic)
  - `ELEVATED`: `0.50 <= attack_score < threshold` (non-standard benign query, e.g. CDN or cloud subdomain, but below operating threshold $\tau = 0.89$; explicitly classified as benign)
- **Suspicious Tier (`attack_score >= threshold`, prediction = `suspicious`):**
  - `CRITICAL`: `attack_score >= threshold` (flags detection alert, $\tau = 0.89$)

---

## 6. Capture Isolation Semantics

- **Grouping Key:** Behavioral state is tracked strictly by `(src_ip, apex_domain)`.
- **Capture Boundary:** To prevent state contamination between different capture files or test sessions, extractors are partitioned by `capture_id`.
  - Queries for `evil.com` in `capture_id="pcap_alpha"` **DO NOT** increment frequencies or update `time_interval` for `evil.com` in `capture_id="pcap_beta"`.
  - For interactive batch requests (`/analyze`, `/analyze/csv`), a dedicated extractor instance is allocated per batch.
  - `/predict` and `/ingest` reuse the long-lived extractor for their `capture_id`.

---

## 7. Error Handling & HTTP Status Codes

All errors return RFC 7807 compatible JSON:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Field 'requested_server_name' is missing or invalid",
    "details": [ ... ]
  }
}
```

- `400 Bad Request`: Empty CSV, invalid CSV header, exceeding maximum file size (15MB) or row limit (20,000).
- `422 Unprocessable Entity`: Validation failure on required fields or RFC domain length violation.
- `500 Internal Server Error`: Unhandled execution fault or missing model bundle.

---

## 8. Persistence & Retention Policies

- **Thread-Safe In-Memory Store (`AppStateStore`):** The CyberTrace reference API synchronizes access via a `threading.Lock` across concurrent workers:
  - `alerts`: Max 500 most recent suspicious events (`label == 1`) in a ring buffer.
  - `statistics`: Dynamic aggregations (`total_processed`, `total_suspicious`, `total_benign`, `suspicious_rate`).
  - `capture_extractors`: Bounded Least-Recently-Used (LRU) cache capped at 256 active capture instances (`OrderedDict` with LRU eviction). When the 257th unique `capture_id` is received, the oldest idle extractor is evicted to prevent unbounded memory growth.
- **No Hardcoded Values:** `/statistics` and `/alerts` strictly derive all metrics from actual processed records.
