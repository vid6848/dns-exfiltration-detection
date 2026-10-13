# Technical Investigation: Analysis of `source_hashes_match = false`

**Investigator:** Soham (Project Coordination & Integration, `soham.prajapati24@spit.ac.in`)  
**Date:** 2026-10-13  
**Status:** Root cause identified (Line Ending Encoding Discrepancy)  
**Applicable Rule:** Under project hard rules, recorded hashes in metadata were **NOT** edited or suppressed.  

---

## 1. Background & Context

In `scripts/summarize_aws_expansion.py:34`, an integrity check verifies that the SHA-256 hashes of the repository source code files match the cryptographic digests recorded in `artifacts/aws_benign_expansion_v0.1/experiment.json['source_sha256']`:

```python
source_hashes_match = all(
    sha256_file(Path(p)) == digest
    for p, digest in log['source_sha256'].items()
)
```

During engineering handoff and Harshul's evaluation benchmarks (PR #3), `source_hashes_match = false` was observed. The handoff notes stated:
> *"The experiment summariser reported a source-hash mismatch whose cause remains unresolved. Investigate rather than editing metadata to suppress the warning."*

---

## 2. Empirical Investigation

### 2.1 File-by-File Hash Comparison
Using a Python script to compare the raw on-disk SHA-256 digest against `experiment.json`:

```
src/features/__init__.py: match=False (expected=77be5bab, actual=1e0a20f8)
src/features/behavioral.py: match=False (expected=97d904ee, actual=c0344c33)
src/features/generate_features_csv.py: match=False (expected=7a90b75d, actual=1336f3f3)
src/features/per_query.py: match=False (expected=bf921fc0, actual=cb97a101)
src/ml/__init__.py: match=True (expected=d2948040, actual=d2948040)
src/ml/artifact.py: match=True (expected=8b482805, actual=8b482805)
src/ml/aws_generalization.py: match=True (expected=be5f1927, actual=be5f1927)
src/ml/data.py: match=True (expected=10286538, actual=10286538)
src/ml/features.py: match=True (expected=4e1764e6, actual=4e1764e6)
src/ml/group_cv.py: match=True (expected=e14d24c6, actual=e14d24c6)
src/ml/robust_train.py: match=True (expected=17ce1ec5, actual=17ce1ec5)
src/ml/train.py: match=True (expected=e221ead4, actual=e221ead4)
src/preprocessing/__init__.py: match=False (expected=62238764, actual=76cdfada)
src/preprocessing/normalizer.py: match=False (expected=4686b3c3, actual=c0528ab2)
src/preprocessing/parser.py: match=False (expected=c8eaf6e7, actual=e6a62207)
src/preprocessing/pipeline.py: match=False (expected=d62e5e43, actual=5452d87d)
src/preprocessing/schema.py: match=False (expected=1427a07a, actual=1233a394)
src/preprocessing/timestamps.py: match=False (expected=7a8a88cd, actual=7e7bf567)
src/preprocessing/validator.py: match=False (expected=237868a2, actual=1413e391)
```

**Observation:** Notice that every file in `src/ml/` matched perfectly, while every file in `src/features/` and `src/preprocessing/` reported a mismatch.

### 2.2 Git History & Commit Cross-Referencing
We inspected `src/features/per_query.py` through `git log`:
- Authored by Harsh Vishwakarma (`Hero`) in commit `88d34a3` on Thu Oct 8 20:17:34 2026.
- The file has had **zero subsequent modifications** in git history: the content on `HEAD` is bit-for-bit identical to commit `88d34a3`.
- The git blob hash at commit `88d34a3` produces SHA-256 `cb97a101b004d331f2cd4dc5887a18bda27a2d6f353ad67cf50f2f5d49240019`.

### 2.3 The Root Cause: Line Ending Encoding (CRLF vs LF)
When examining the byte stream of `src/features/per_query.py` on macOS/Linux, line endings are Unix LF (`\n`, `0x0A`).
When replacing all LF characters with Windows CRLF (`\r\n`, `0x0D 0x0A`):

```python
with open('src/features/per_query.py', 'rb') as f:
    lf_data = f.read()
crlf_data = lf_data.replace(b'\n', b'\r\n')

# LF SHA-256:   cb97a101b004d331f2cd4dc5887a18bda27a2d6f353ad67cf50f2f5d49240019
# CRLF SHA-256: bf921fc0c49b0c38bda451903adc168536f812082e458f0025d751d15cbae71f
# Recorded in experiment.json: bf921fc0c49b0c38bda451903adc168536f812082e458f0025d751d15cbae71f
```

The CRLF hash is an **exact, character-for-character match** with the recorded hash in `experiment.json`!

Testing all 19 files across the repository with CRLF normalization:
- `src/features/*`: **100% Match with CRLF**
- `src/preprocessing/*`: **100% Match with CRLF**
- `src/ml/*`: **100% Match with LF**

---

## 3. Findings & Technical Diagnosis

1. **Operating System Divergence during Experiment Logging:**
   - Preprocessing and feature engineering modules were authored on a Windows workstation (where Git checked out files with `core.autocrlf=true`, converting newlines to `\r\n`).
   - When the training experiment script (`scripts/summarize_aws_expansion.py` / `src/ml/train.py`) logged the source code digests on that environment, `sha256_file()` opened files in binary mode (`open(path, 'rb')`), hashing the on-disk Windows CRLF bytes for preprocessing and features.
   - Files in `src/ml/` were committed and hashed with LF endings.
2. **Git Repository Normalization:**
   - When files are checked out on Linux/macOS or with default Git newline normalization, files are stored as LF in the Git object store.
   - Consequently, hashing the on-disk file in binary mode on Unix yields the LF hash, causing `source_hashes_match` to return `False`.
3. **Current State of the Summarizer:**
   - Because the recorded hashes remain frozen as CRLF in `experiment.json`, running `python -m scripts.summarize_aws_expansion` on Unix platforms still evaluates `source_hashes_match = false` as originally recorded.

---

## 4. Policy Compliance & Future Recommendation

- **Policy Adherence:** As required by the hard constraints, **we did NOT alter `experiment.json` or `verification.json` to artificially force this check to pass**.
- **Future Project Recommendation:**
  For future releases or retraining phases, enforce repository-wide line ending consistency by adding a `.gitattributes` configuration at repository root:
  ```gitattributes
  * text=auto eol=lf
  *.py text eol=lf
  ```
  And in Python hashing utilities, hash normalized decoded text streams (e.g. `f.read().replace('\r\n', '\n').encode('utf-8')`) rather than raw OS-dependent filesystem bytes.
- This investigation proves that the underlying source code algorithms and implementations are 100% intact, bit-for-bit identical in algorithmic semantics, and that the discrepancy is solely an operating system newline serialization artifact.
