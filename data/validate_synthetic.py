#!/usr/bin/env python3
"""
Synthetic Dataset Validation Script
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CyberTrace)

Validates synthetic DNS exfiltration CSV files against research and engineering contracts:
1. Verifies exact 10-column schema and column order matching benign_dns_v0.1.csv.
2. Asserts label is strictly 1 (100% attack traffic).
3. Verifies zero missing / null / empty values.
4. Asserts zero completely duplicated rows.
5. Verifies timestamps fall within valid time bounds and follow YYYY-MM-DD HH:MM:SS.mmm format.
6. Verifies RFC-compliant DNS domain structure (label length <= 63, total length <= 253).
7. Re-computes and checks all 4 numerical feature formulas:
   - dns_query_length == len(requested_server_name)
   - dns_query_entropy == Shannon entropy (base 2) of complete string
   - dns_subdomain_count == dot-separated label count
   - dns_numerical_ratio == digit count / length
8. Asserts diversity: multiple base domains, multiple source IPs, and varied structural lengths.
9. Outputs explicit PASS/FAIL per check and overall validation summary.
"""

import argparse
from collections import Counter
import csv
from datetime import datetime
import math
from pathlib import Path
import re
import sys
from typing import List, Tuple

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


def shannon_entropy(s: str) -> float:
    """Computes reference Shannon entropy (base 2) over full string."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())


def validate_synthetic_file(
    file_path: Path,
    expected_rows: int = None,
    min_time_str: str = "2025-06-13 09:00:00.000",
    max_time_str: str = "2025-06-14 10:00:00.000",
) -> Tuple[bool, dict]:
    """Runs rigorous validation checks on a synthetic dataset."""
    print("=" * 72)
    print("VALIDATING SYNTHETIC DNS EXFILTRATION DATASET")
    print(f"Target: {file_path}")
    print("=" * 72)

    if not file_path.exists():
        print(f"[FAIL] Target file does not exist: {file_path}")
        return False, {}

    all_passed = True
    stats = {}

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            actual_cols = next(reader)
        except StopIteration:
            print("[FAIL] File is empty.")
            return False, {}

        # Check 1: Columns
        cols_match = actual_cols == EXPECTED_COLUMNS
        print("\n[Check 1] Expected Columns Verification:")
        print(f"    Expected ({len(EXPECTED_COLUMNS)}): {EXPECTED_COLUMNS}")
        print(f"    Actual   ({len(actual_cols)}): {actual_cols}")
        if cols_match:
            print("    --> Result: [PASS] All 10 columns exist in exact order.")
        else:
            print("    --> Result: [FAIL] Columns do not match expected contract.")
            all_passed = False

        col_idx = {name: i for i, name in enumerate(actual_cols)}

        num_rows = 0
        missing = [0] * len(actual_cols)
        seen_rows = set()
        duplicate_count = 0
        non_one_labels = 0

        # Mathematical checks
        length_mismatches = 0
        entropy_mismatches = 0
        subdomain_mismatches = 0
        numerical_ratio_mismatches = 0

        # Domain validity checks
        rfc_violations = 0

        # Diversity tracking
        unique_fqdns = set()
        unique_src_ips = set()
        unique_dst_ips = set()
        base_domains = set()
        lengths = []
        entropies = []
        subdomain_counts = []
        num_ratios = []
        timestamps = []

        min_bound_dt = datetime.strptime(min_time_str, "%Y-%m-%d %H:%M:%S.%f")
        max_bound_dt = datetime.strptime(max_time_str, "%Y-%m-%d %H:%M:%S.%f")
        out_of_bound_timestamps = 0

        for line_num, row in enumerate(reader, start=2):
            num_rows += 1
            if len(row) != len(actual_cols):
                all_passed = False
                continue

            for i, val in enumerate(row):
                if val is None or val.strip() == "":
                    missing[i] += 1

            row_tuple = tuple(row)
            if row_tuple in seen_rows:
                duplicate_count += 1
            else:
                seen_rows.add(row_tuple)

            # Check label == 1
            lbl = row[col_idx["label"]]
            if lbl not in ("1", "1.0"):
                non_one_labels += 1

            # Check timestamp format & bounds
            ts_str = row[col_idx["timestamp"]]
            timestamps.append(ts_str)
            try:
                row_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                if not (min_bound_dt <= row_dt <= max_bound_dt):
                    out_of_bound_timestamps += 1
            except ValueError:
                out_of_bound_timestamps += 1

            # Diversity tracking
            src = row[col_idx["src_ip"]]
            dst = row[col_idx["dst_ip"]]
            fqdn = row[col_idx["requested_server_name"]]
            unique_src_ips.add(src)
            unique_dst_ips.add(dst)
            unique_fqdns.add(fqdn)

            # Extract base domain (last 2 labels)
            parts = fqdn.split(".")
            if len(parts) >= 2:
                base_domains.add(".".join(parts[-2:]))

            # Domain structure RFC checks
            if len(fqdn) > 253 or any(len(p) > 63 for p in parts):
                rfc_violations += 1

            # Parse features from row
            try:
                row_len = int(row[col_idx["dns_query_length"]])
                row_ent = float(row[col_idx["dns_query_entropy"]])
                row_sub = int(row[col_idx["dns_subdomain_count"]])
                row_num = float(row[col_idx["dns_numerical_ratio"]])
            except ValueError:
                all_passed = False
                continue

            lengths.append(row_len)
            entropies.append(row_ent)
            subdomain_counts.append(row_sub)
            num_ratios.append(row_num)

            # Exact re-calculation
            calc_len = len(fqdn)
            calc_ent = shannon_entropy(fqdn)
            calc_sub = len(parts)
            calc_num = sum(c.isdigit() for c in fqdn) / calc_len if calc_len > 0 else 0.0

            if calc_len != row_len:
                length_mismatches += 1
            if abs(calc_ent - row_ent) > 1e-5:
                entropy_mismatches += 1
            if calc_sub != row_sub:
                subdomain_mismatches += 1
            if abs(calc_num - row_num) > 1e-5:
                numerical_ratio_mismatches += 1

    # Check 2: Dimensions
    print(f"\n[Check 2] Dimensions:")
    print(f"    - Total Rows:    {num_rows:,}")
    print(f"    - Total Columns: {len(actual_cols)}")
    if expected_rows is not None and num_rows != expected_rows:
        print(f"    --> Result: [FAIL] Expected {expected_rows:,} rows, got {num_rows:,}.")
        all_passed = False
    elif num_rows > 0:
        print("    --> Result: [PASS] Valid non-empty dataset dimensions.")
    else:
        print("    --> Result: [FAIL] Dataset is empty.")
        all_passed = False

    # Check 3: Missing values
    print(f"\n[Check 3] Missing Values:")
    total_missing = sum(missing)
    if total_missing == 0:
        print("    --> Result: [PASS] 0 missing values across all columns.")
    else:
        print(f"    --> Result: [FAIL] Found {total_missing} missing values.")
        all_passed = False

    # Check 4: Duplicates
    print(f"\n[Check 4] Duplicate Rows:")
    print(f"    - Duplicates: {duplicate_count}")
    if duplicate_count == 0:
        print("    --> Result: [PASS] 0 duplicate rows.")
    else:
        print(f"    --> Result: [FAIL] Found {duplicate_count} duplicate rows.")
        all_passed = False

    # Check 5: Label distribution
    print(f"\n[Check 5] Label Verification:")
    print(f"    - Non-attack labels (label != 1): {non_one_labels}")
    if non_one_labels == 0:
        print("    --> Result: [PASS] All labels are strictly 1 (100% attack traffic).")
    else:
        print(f"    --> Result: [FAIL] Detected {non_one_labels} non-1 labels.")
        all_passed = False

    # Check 6: Timestamps
    print(f"\n[Check 6] Timestamp Bounds ({min_time_str} to {max_time_str}):")
    print(f"    - Out of bound timestamps: {out_of_bound_timestamps}")
    if timestamps:
        timestamps.sort()
        print(f"    - Earliest timestamp: {timestamps[0]}")
        print(f"    - Latest timestamp:   {timestamps[-1]}")
    if out_of_bound_timestamps == 0:
        print("    --> Result: [PASS] All timestamps are strictly within configured bounds.")
    else:
        print(f"    --> Result: [FAIL] Found {out_of_bound_timestamps} timestamps out of range.")
        all_passed = False

    # Check 7: Domain RFC Structure
    print(f"\n[Check 7] Domain RFC Structure:")
    print(f"    - RFC violations: {rfc_violations}")
    if rfc_violations == 0:
        print("    --> Result: [PASS] All domains conform to DNS RFC label and length limits.")
    else:
        print(f"    --> Result: [FAIL] Found {rfc_violations} RFC-violating domains.")
        all_passed = False

    # Check 8: Feature Mathematical Accuracy
    print(f"\n[Check 8] Mathematical Feature Formulas:")
    print(f"    - Query length mismatches:    {length_mismatches}")
    print(f"    - Query entropy mismatches:   {entropy_mismatches}")
    print(f"    - Subdomain count mismatches: {subdomain_mismatches}")
    print(f"    - Numerical ratio mismatches: {numerical_ratio_mismatches}")
    math_failures = length_mismatches + entropy_mismatches + subdomain_mismatches + numerical_ratio_mismatches
    if math_failures == 0:
        print("    --> Result: [PASS] 100% of precomputed features match exact reference formulas.")
    else:
        print(f"    --> Result: [FAIL] Detected {math_failures} feature formula discrepancies.")
        all_passed = False

    # Check 9: Diversity & Non-triviality
    print(f"\n[Check 9] Diversity & Non-triviality:")
    print(f"    - Unique Queried FQDNs: {len(unique_fqdns):,}")
    print(f"    - Unique Base Domains:  {len(base_domains)} ({sorted(list(base_domains))[:5]}...)")
    print(f"    - Unique Source IPs:    {len(unique_src_ips)} ({sorted(list(unique_src_ips))})")
    print(f"    - Unique Resolvers:     {len(unique_dst_ips)} ({sorted(list(unique_dst_ips))})")
    diversity_ok = len(base_domains) >= 2 and len(unique_src_ips) >= 2 and len(unique_dst_ips) >= 2
    if diversity_ok:
        print("    --> Result: [PASS] Multiple base domains, source IPs, and resolvers present.")
    else:
        print("    --> Result: [FAIL] Insufficient diversity in domains, IPs, or resolvers.")
        all_passed = False

    # Summary Stats
    if lengths:
        stats = {
            "num_rows": num_rows,
            "unique_fqdns": len(unique_fqdns),
            "base_domains_count": len(base_domains),
            "source_ips_count": len(unique_src_ips),
            "resolvers_count": len(unique_dst_ips),
            "query_length_range": (min(lengths), max(lengths)),
            "entropy_range": (round(min(entropies), 4), round(max(entropies), 4)),
            "subdomain_count_range": (min(subdomain_counts), max(subdomain_counts)),
            "numerical_ratio_range": (round(min(num_ratios), 4), round(max(num_ratios), 4)),
            "timestamp_range": (timestamps[0], timestamps[-1]),
            "duplicates": duplicate_count,
            "missing_values": total_missing,
        }

    print("\n" + "=" * 72)
    if all_passed:
        print("OVERALL VALIDATION RESULT: [PASS] ALL SYNTHETIC CHECKS PASSED")
    else:
        print("OVERALL VALIDATION RESULT: [FAIL] ONE OR MORE CHECKS FAILED")
    print("=" * 72)

    return all_passed, stats


def main():
    parser = argparse.ArgumentParser(
        description="Validate synthetic DNS exfiltration CSV dataset."
    )
    parser.add_argument(
        "--target",
        type=str,
        default="data/processed/synthetic_exfiltration_v0.1.csv",
        help="Target CSV file to validate (default: data/processed/synthetic_exfiltration_v0.1.csv)",
    )
    parser.add_argument(
        "--expected-rows",
        type=int,
        default=None,
        help="Optional expected row count to enforce",
    )
    parser.add_argument(
        "--min-time",
        type=str,
        default="2025-06-13 09:00:00.000",
        help="Earliest allowed timestamp",
    )
    parser.add_argument(
        "--max-time",
        type=str,
        default="2025-06-14 10:00:00.000",
        help="Latest allowed timestamp",
    )

    args = parser.parse_args()
    target_path = Path(args.target)
    success, _ = validate_synthetic_file(
        target_path,
        expected_rows=args.expected_rows,
        min_time_str=args.min_time,
        max_time_str=args.max_time,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
