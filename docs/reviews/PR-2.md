# Post-Hoc Review: PR #2 (Preprocessing, Normalization & Leakage Elimination)

**PR:** #2 (`yash/preprocessing-and-parsing` -> `main`)  
**Author:** Yash (`Astr0876`)  
**Reviewer:** Soham (Project Coordination & Integration)  
**Date:** 2026-10-13  
**Status:** Merged  

---

## 1. Scope & Deliverable Overview
PR #2 established the foundation of the CyberTrace data pipeline:
- Preprocessing modules: `src/preprocessing/parser.py`, `normalizer.py`, `pipeline.py`, `schema.py`, `timestamps.py`, `validator.py`
- Test suite: `tests/test_preprocessing.py` (22 tests)
- Handoff specifications: `data/preprocessing_handoff.md`
- Processed output: `data/processed/cleaned_unified_v0.1.csv` (109,989 records)

## 2. Technical Strengths
- **Rigorous Data Leakage Guardrails:** Built `verify_ml_feature_safety()` in `src/preprocessing/schema.py:120-135`, strictly forbidding `src_ip`, `dst_ip`, `timestamp`, `requested_server_name`, `label`, and `source` from entering machine learning feature sets.
- **Robust Domain Parsing:** Normalizes domains by converting to lowercase, stripping trailing root dots, and decomposing FQDNs into `apex_domain`, `subdomain`, `tld`, and label metrics.
- **Thorough Unit Testing:** `tests/test_preprocessing.py` thoroughly verifies invalid IPv4/IPv6 handling, domain edge cases, RFC length compliance, and timestamp parsing.

## 3. Concrete Issues & Code References
1. **Dependency Packaging Gap (The Broken `requirements.txt`):**
   - The PR and repository documentation state that users can run `pip install -r requirements.txt`. However, requirements were split across `requirements-data.txt`, `requirements-training.txt`, and `requirements-dev.txt`, with **no top-level `requirements.txt` file created in the root directory**.
   - As a consequence, running `pip install -r requirements.txt` as instructed in the project report fails immediately with `ERROR: Could not open requirements file: [Errno 2] No such file or directory: 'requirements.txt'`.
2. **Epoch Time Floating Precision:**
   - In `src/preprocessing/timestamps.py:45-55`, timestamps are converted to Unix epoch seconds (`float`). For millisecond-resolution captures, Python 64-bit float maintains sufficient precision, but integer nanosecond/microsecond representations or strict decimal parsing should be noted for high-throughput packet pipelines.

## 4. Downstream Integration Impact & Resolution
- In `integration/soham-e2e`, I am adding the missing top-level `requirements.txt` consolidating `-r requirements-data.txt`, `-r requirements-training.txt`, and `-r requirements-dev.txt`.
- The preprocessing pipeline is reused directly in `api/main.py` and `api/routes/analyze_csv.py` via `PreprocessingPipeline(check_duplicates=False)`.
