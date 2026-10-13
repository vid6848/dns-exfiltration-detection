# Post-Hoc Review: PR #1 (Synthetic DNS Exfiltration Dataset v0.1)

**PR:** #1 (`param/synthetic-exfiltration-dataset` -> `main`)  
**Author:** Param (`param7862989-ops`)  
**Reviewer:** Soham (Project Coordination & Integration)  
**Date:** 2026-10-13  
**Status:** Merged  

---

## 1. Scope & Deliverable Overview
PR #1 delivered the synthetic attack dataset generation engine and initial dataset artifacts:
- Generator script: `data/generate_synthetic_exfiltration.py`
- Strict 10-column schema validator: `data/validate_synthetic.py`
- Methodology documentation: `data/synthetic_generation.md`
- Data samples: `data/processed/synthetic_dev_sample_100.csv` and `data/processed/synthetic_exfiltration_v0.1.csv` (10,000 records)

## 2. Technical Strengths
- **Diverse Attack Encodings:** Emulates multiple real-world exfiltration channels: Base32, Base64-like, and hexadecimal tunneling patterns (emulating dnscat2 and iodine).
- **Temporal Pacing Diversity:** Synthesizes both high-frequency bursts (queries spaced sub-second) and low-and-slow drip tunneling (delays spanning 5 to 60 seconds).
- **Client IP Blending:** Explicitly includes private network client IPs, including the benign capture's dominant IP `10.0.30.186` (weighted at 50%), preventing downstream classifiers from exploiting IP identity as an artificial shortcut for detection.

## 3. Concrete Issues & Code References
1. **Schema Column Name Discrepancies:**
   - In `data/generate_synthetic_exfiltration.py:31-42`, columns are generated with names like `dns_query_length`, `dns_query_entropy`, `dns_subdomain_count`, `dns_numerical_ratio`.
   - Downstream, Yash's canonical preprocessing (`src/preprocessing/schema.py`) and Hero's feature extractors (`src/features/per_query.py`) use standard names (`requested_server_name`, `query_length`, `entropy`, `digit_ratio`, `subdomain_length`). Preprocessing had to normalize or drop these synthetic-only columns to avoid conflicting feature definitions.
2. **Missing Unit Tests:**
   - While `data/validate_synthetic.py` performs CLI dataset integrity validation, no automated `pytest` suite was committed with PR #1 to test the generation script functions (`compute_shannon_entropy`, `compute_features`) against regression.

## 4. Downstream Integration Impact & Resolution
- Yash's PR #2 resolved the column alignment by introducing `src/preprocessing/normalizer.py` and `schema.py`, which strips unneeded auxiliary columns before feature computation.
- In `integration/soham-e2e`, the formal data schema contract is documented in `docs/CONTRACTS.md`, ensuring all future dataset additions adhere to unified naming conventions.
