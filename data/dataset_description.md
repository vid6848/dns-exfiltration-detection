# Dataset Description

## 1. Purpose
This dataset is prepared for the academic project **"DNS Exfiltration Detection Using Network Traffic Analysis"** (CE305/CS305). It currently represents the benign portion of the dataset (`benign_dns_v0.1`), providing a clean baseline of legitimate DNS queries against which DNS-based exfiltration and tunnelling techniques can be evaluated.

---

## 2. Dataset Provenance
- **Source:** Mendeley Data — *DNS Data Exfiltration Dataset*
- **Usage:** Academic and research purposes only.
- **Raw File:** `data/raw/dataset_dns_exfiltration.csv` (preserved in its original state without modification).
- **Processed File:** `data/processed/benign_dns_v0.1.csv`
- **Source Dataset Size:** 109,359 total network flow records.
- **Original Label Distribution:**
  - `0` (Benign): 99,995 records (91.44%)
  - `1` (DNS Exfiltration): 9,364 records (8.56%)

The raw data was downloaded directly from the source repository and is permanently retained in `data/raw/` for reproducibility and auditability.

---

## 3. Dataset Version
- **Version Identifier:** `benign_dns_v0.1`
- **Description:** This version represents the initial, filtered benign DNS dataset extracted from the original Mendeley dataset for baseline feature analysis, exploratory data analysis (EDA), and machine learning pipeline development.

---

## 4. Label Definition
In the source and processed datasets:
- **`label = 0`** &rarr; **Benign DNS Traffic** (normal, legitimate domain name resolution queries).
- **`label = 1`** &rarr; **DNS Exfiltration** (covert channel communication where data is encoded within DNS query labels).

The current processed dataset (`benign_dns_v0.1.csv`) contains **strictly `label = 0`** records.

---

## 5. CSV Fields
The processed file `data/processed/benign_dns_v0.1.csv` contains the following 10 fields in exact order:

| Column Name | Inferred Type | Description |
|---|---|---|
| `timestamp` | string (datetime) | Flow start timestamp (derived directly from the original `start_time` field). |
| `src_ip` | string | Source IP address originating the DNS request (e.g., internal client IP `10.0.30.186`). |
| `dst_ip` | string | Destination IP address receiving the DNS request (e.g., DNS resolver `8.8.8.8`). |
| `requested_server_name` | string | Fully Qualified Domain Name (FQDN) or domain queried in the DNS request. |
| `dns_query_length` | integer | Total character count of the DNS query string. |
| `dns_query_entropy` | float | Shannon entropy score of the query string, reflecting character randomness. |
| `dns_subdomain_count` | integer | Number of subdomain labels separated by dots within the domain name. |
| `dns_numerical_ratio` | float | Proportion of numerical digits (0–9) relative to the total query length. |
| `label` | integer | Traffic classification label (`0` = Benign DNS Traffic). |
| `source` | string | Origin identifier: `"Mendeley DNS Data Exfiltration Dataset"`. |

---

## 6. Dataset Statistics
- **Original Source Dataset:** 109,359 records
- **Original Benign Records (`label = 0`):** 99,995 records
- **Original Exfiltration Records (`label = 1`):** 9,364 records
- **Prepared Benign Records (`benign_dns_v0.1`):** 99,989 records
- **Number of Columns:** 10
- **Unique Queried Domains:** 6,225 unique domain names

*Duplicate handling note:* Exactly 6 records were removed during filtering because they were completely duplicated across the selected 10 columns (identical timestamp, IP endpoints, queried domain, and extracted DNS feature values). The original raw dataset contained 0 duplicates across its full 20 columns because those flows differed only by ephemeral source port numbers (`src_port`).

---

## 7. Missing Values
- **Missing / Null Count:** **0** across all 10 columns.
- The dataset is 100% complete with no empty strings, nulls, or NaN entries.

---

## 8. Duplicate Validation
- **Original Raw Dataset (20 columns):** 0 completely duplicated rows.
- **Prepared Benign Dataset before deduplication (10 columns):** 6 completely duplicated rows across the projected feature set.
- **Prepared Benign Dataset after deduplication (`benign_dns_v0.1.csv`):** **0 completely duplicated rows**.

---

## 9. Class Balance
The current file `benign_dns_v0.1.csv` is intentionally **benign-only** (`label = 0` for 100% of records) and is therefore not class-balanced. The original source dataset contains both benign (99,995) and exfiltration (9,364) records. This file isolates the benign portion for feature baseline characterization and modular data preparation; it has not been artificially balanced or altered.

---

## 10. Data Processing
The pipeline to produce `benign_dns_v0.1.csv` followed these steps:
1. **Preservation:** The original source dataset was placed in `data/raw/dataset_dns_exfiltration.csv` and kept immutable (read-only).
2. **Filtering:** Extracted only flows where `label == 0` (99,995 records).
3. **Column Projection:** Retained the 10 target columns in the required sequence.
4. **Field Mapping & Metadata:** Renamed `start_time` to `timestamp` and appended the `source` field set to `"Mendeley DNS Data Exfiltration Dataset"`.
5. **Deduplication:** Identified and removed 6 completely duplicated records across the 10 selected columns.
6. **Export:** Exported the resulting 99,989 records to `data/processed/benign_dns_v0.1.csv`.

---

## 11. Validation Results

| Validation Check | Expected Result | Actual Result | Status |
|---|---|---|:---:|
| Total Rows | 99,989 | 99,989 | **PASS** |
| Total Columns | 10 | 10 | **PASS** |
| Target Columns Present | All 10 expected | All 10 present in order | **PASS** |
| Label Value | 0 only | 100% (99,989 rows) | **PASS** |
| Missing Values | 0 in all columns | 0 missing | **PASS** |
| Completely Duplicated Rows | 0 | 0 | **PASS** |
| Unique Domains | 6,225 | 6,225 | **PASS** |

---

## 12. Limitations
1. **Benign-Only Content:** This processed file contains only benign traffic. DNS exfiltration attack flows must be integrated separately to train and evaluate supervised classification models.
2. **Dataset Representativeness:** Because this data is derived from the Mendeley DNS Data Exfiltration testbed environment, its traffic patterns reflect the simulated network environment in which it was captured.
3. **Derived Features:** Statistical features such as query entropy and numerical ratio were pre-computed in the original dataset and preserved as-is. Additional contextual or temporal window features will need to be calculated as required by subsequent modeling steps.
