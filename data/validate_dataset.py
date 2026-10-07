#!/usr/bin/env python3
"""
Dataset Validation Script
Project: DNS Exfiltration Detection Using Network Traffic Analysis

Validates data/processed/benign_dns_v0.1.csv against expected academic standards:
1. Verifies that all 10 expected columns exist.
2. Checks total rows and columns.
3. Checks for missing / null values in all columns.
4. Checks for completely duplicated rows.
5. Checks label distribution and verifies that 100% of labels are 0.
6. Computes the count of unique queried domains (requested_server_name).
7. Outputs explicit PASS/FAIL statuses and an overall validation summary.
"""

from pathlib import Path
import sys

# Locate processed dataset relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CSV_PATH = PROJECT_ROOT / "data" / "processed" / "benign_dns_v0.1.csv"

EXPECTED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "requested_server_name",
    "dns_query_length",
    "dns_query_entropy",
    "dns_subdomain_count",
    "dns_numerical_ratio",
    "label",
    "source",
]


def validate_with_pandas(file_path: Path) -> bool:
    import pandas as pd

    print("=" * 72)
    print("VALIDATING BENIGN DNS DATASET (benign_dns_v0.1.csv)")
    print(f"Target: {file_path}")
    print("=" * 72)

    df = pd.read_csv(file_path)
    all_passed = True

    # 1. Column existence and ordering check
    actual_cols = list(df.columns)
    cols_match = actual_cols == EXPECTED_COLUMNS
    print(f"\n[Check 1] Expected Columns Verification:")
    print(f"    Expected ({len(EXPECTED_COLUMNS)}): {EXPECTED_COLUMNS}")
    print(f"    Actual   ({len(actual_cols)}): {actual_cols}")
    if cols_match:
        print("    --> Result: [PASS] All 10 columns exist in exact order.")
    else:
        print("    --> Result: [FAIL] Columns do not match expected specification.")
        all_passed = False

    # 2. Dimensions check
    num_rows, num_cols = df.shape
    print(f"\n[Check 2] Dataset Dimensions:")
    print(f"    - Total Rows:    {num_rows:,}")
    print(f"    - Total Columns: {num_cols}")
    if num_rows == 99989 and num_cols == 10:
        print("    --> Result: [PASS] Dimensions match expected (99,989 rows, 10 columns).")
    else:
        print("    --> Result: [FAIL] Unexpected row or column count.")
        all_passed = False

    # 3. Missing values check
    print(f"\n[Check 3] Missing Values per Column:")
    missing = df.isnull().sum()
    total_missing = int(missing.sum())
    for col, count in missing.items():
        print(f"    - {col:<26}: {count} missing")
    if total_missing == 0:
        print("    --> Result: [PASS] 0 missing values across all columns.")
    else:
        print(f"    --> Result: [FAIL] Found {total_missing} missing values.")
        all_passed = False

    # 4. Completely duplicated rows check
    print(f"\n[Check 4] Completely Duplicated Rows:")
    duplicate_count = int(df.duplicated().sum())
    print(f"    - Duplicate rows count: {duplicate_count}")
    if duplicate_count == 0:
        print("    --> Result: [PASS] 0 completely duplicated rows.")
    else:
        print(f"    --> Result: [FAIL] Found {duplicate_count} duplicate rows.")
        all_passed = False

    # 5. Label distribution & verification that all labels are 0
    print(f"\n[Check 5] Label Distribution ('label' column):")
    label_counts = df["label"].value_counts(dropna=False).to_dict()
    for lbl, cnt in label_counts.items():
        print(f"    - Label '{lbl}': {cnt:,} rows")
    
    unique_labels = list(label_counts.keys())
    only_zero = (len(unique_labels) == 1 and str(unique_labels[0]) in ("0", "0.0"))
    if only_zero:
        print("    --> Result: [PASS] All labels are strictly 0 (100% benign traffic).")
    else:
        print(f"    --> Result: [FAIL] Non-zero or multiple labels detected: {unique_labels}")
        all_passed = False

    # 6. Unique queried domains count
    print(f"\n[Check 6] Domain Name Diversity:")
    if "requested_server_name" in df.columns:
        unique_domains = df["requested_server_name"].nunique()
        print(f"    - Unique Queried Domains: {unique_domains:,}")
        if unique_domains > 0:
            print("    --> Result: [PASS] Valid domain distribution present.")
        else:
            print("    --> Result: [FAIL] No domain values found.")
            all_passed = False
    else:
        print("    --> Result: [FAIL] 'requested_server_name' column missing.")
        all_passed = False

    # Final overall result
    print("\n" + "=" * 72)
    if all_passed:
        print("OVERALL VALIDATION RESULT: [PASS] ALL CHECKS PASSED")
    else:
        print("OVERALL VALIDATION RESULT: [FAIL] ONE OR MORE CHECKS FAILED")
    print("=" * 72)

    return all_passed


def validate_with_csv(file_path: Path) -> bool:
    import csv
    from collections import Counter

    print("=" * 72)
    print("VALIDATING BENIGN DNS DATASET (via standard library csv)")
    print(f"Target: {file_path}")
    print("=" * 72)

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            actual_cols = next(reader)
        except StopIteration:
            print("[FAIL] File is empty.")
            return False

        all_passed = True

        # 1. Column check
        cols_match = actual_cols == EXPECTED_COLUMNS
        print(f"\n[Check 1] Expected Columns Verification:")
        print(f"    Expected ({len(EXPECTED_COLUMNS)}): {EXPECTED_COLUMNS}")
        print(f"    Actual   ({len(actual_cols)}): {actual_cols}")
        if cols_match:
            print("    --> Result: [PASS] All 10 columns exist in exact order.")
        else:
            print("    --> Result: [FAIL] Columns do not match expected specification.")
            all_passed = False

        label_idx = actual_cols.index("label") if "label" in actual_cols else -1
        domain_idx = actual_cols.index("requested_server_name") if "requested_server_name" in actual_cols else -1

        num_rows = 0
        missing = [0] * len(actual_cols)
        label_counter = Counter()
        seen = set()
        duplicate_count = 0
        unique_domains = set()

        for row in reader:
            num_rows += 1
            for i, val in enumerate(row):
                if val is None or val.strip() == "":
                    missing[i] += 1
            if label_idx != -1 and label_idx < len(row):
                label_counter[row[label_idx]] += 1
            if domain_idx != -1 and domain_idx < len(row):
                unique_domains.add(row[domain_idx])
            row_tuple = tuple(row)
            if row_tuple in seen:
                duplicate_count += 1
            else:
                seen.add(row_tuple)

    # 2. Dimensions check
    num_cols = len(actual_cols)
    print(f"\n[Check 2] Dataset Dimensions:")
    print(f"    - Total Rows:    {num_rows:,}")
    print(f"    - Total Columns: {num_cols}")
    if num_rows == 99989 and num_cols == 10:
        print("    --> Result: [PASS] Dimensions match expected (99,989 rows, 10 columns).")
    else:
        print("    --> Result: [FAIL] Unexpected row or column count.")
        all_passed = False

    # 3. Missing values check
    print(f"\n[Check 3] Missing Values per Column:")
    total_missing = sum(missing)
    for col, cnt in zip(actual_cols, missing):
        print(f"    - {col:<26}: {cnt} missing")
    if total_missing == 0:
        print("    --> Result: [PASS] 0 missing values across all columns.")
    else:
        print(f"    --> Result: [FAIL] Found {total_missing} missing values.")
        all_passed = False

    # 4. Completely duplicated rows check
    print(f"\n[Check 4] Completely Duplicated Rows:")
    print(f"    - Duplicate rows count: {duplicate_count}")
    if duplicate_count == 0:
        print("    --> Result: [PASS] 0 completely duplicated rows.")
    else:
        print(f"    --> Result: [FAIL] Found {duplicate_count} duplicate rows.")
        all_passed = False

    # 5. Label distribution check
    print(f"\n[Check 5] Label Distribution ('label' column):")
    for lbl, cnt in label_counter.items():
        print(f"    - Label '{lbl}': {cnt:,} rows")
    only_zero = (list(label_counter.keys()) == ["0"])
    if only_zero:
        print("    --> Result: [PASS] All labels are strictly 0 (100% benign traffic).")
    else:
        print(f"    --> Result: [FAIL] Non-zero or multiple labels detected: {list(label_counter.keys())}")
        all_passed = False

    # 6. Unique domains check
    print(f"\n[Check 6] Domain Name Diversity:")
    print(f"    - Unique Queried Domains: {len(unique_domains):,}")
    if len(unique_domains) > 0:
        print("    --> Result: [PASS] Valid domain distribution present.")
    else:
        print("    --> Result: [FAIL] No domain values found.")
        all_passed = False

    # Final overall result
    print("\n" + "=" * 72)
    if all_passed:
        print("OVERALL VALIDATION RESULT: [PASS] ALL CHECKS PASSED")
    else:
        print("OVERALL VALIDATION RESULT: [FAIL] ONE OR MORE CHECKS FAILED")
    print("=" * 72)

    return all_passed


def main():
    if not CSV_PATH.exists():
        print(f"ERROR: Target file not found at {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    try:
        import pandas as pd
        success = validate_with_pandas(CSV_PATH)
    except ImportError:
        success = validate_with_csv(CSV_PATH)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
