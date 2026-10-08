"""
Dataset and Record Validation Module
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

Validates incoming records against:
- Data contract schema compliance.
- Null / empty value constraints.
- IP address syntactic correctness (IPv4 / IPv6).
- RFC domain constraints (label <= 63 chars, total <= 253 chars).
- Strict binary label requirement (label in {0, 1}).
- Duplicate identification.
"""

from collections import Counter
from dataclasses import dataclass, field
import ipaddress
from typing import Dict, List, Optional, Tuple, Set, Any

from .schema import RawRecord, EXPECTED_DATASET_COLUMNS
from .normalizer import normalize_domain, is_valid_fqdn
from .timestamps import parse_timestamp


@dataclass
class ValidationReport:
    """Summary of validation outcomes across a dataset."""
    total_records: int = 0
    valid_records: int = 0
    invalid_records: int = 0
    duplicate_records: int = 0
    missing_value_counts: Dict[str, int] = field(default_factory=lambda: Counter())
    label_distribution: Dict[int, int] = field(default_factory=lambda: Counter())
    validation_errors: List[str] = field(default_factory=list)

    @property
    def is_successful(self) -> bool:
        return self.invalid_records == 0 and self.valid_records > 0

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "DATASET PREPROCESSING VALIDATION REPORT",
            "=" * 60,
            f"Total Records Processed: {self.total_records:,}",
            f"Valid Records:           {self.valid_records:,}",
            f"Invalid Records:         {self.invalid_records:,}",
            f"Duplicate Records:       {self.duplicate_records:,}",
            "-" * 60,
            "Label Distribution:",
        ]
        for lbl, count in self.label_distribution.items():
            desc = "Benign" if lbl == 0 else "Exfiltration" if lbl == 1 else "Unknown"
            lines.append(f"  - Label {lbl} ({desc}): {count:,} records")
        
        if self.missing_value_counts:
            lines.append("-" * 60)
            lines.append("Missing Values Detected:")
            for col, count in self.missing_value_counts.items():
                if count > 0:
                    lines.append(f"  - {col}: {count:,}")

        if self.validation_errors:
            lines.append("-" * 60)
            lines.append(f"Sample Validation Errors ({min(5, len(self.validation_errors))} shown):")
            for err in self.validation_errors[:5]:
                lines.append(f"  [ERROR] {err}")

        lines.append("=" * 60)
        lines.append(f"OVERALL STATUS: {'[PASS]' if self.is_successful else '[FAIL]'}")
        lines.append("=" * 60)
        return "\n".join(lines)


def is_valid_ip(ip_str: str) -> bool:
    """Checks whether a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_raw_record(record: RawRecord) -> Tuple[bool, Optional[str]]:
    """
    Validates a single raw record against syntax, contract, and typing constraints.

    Returns:
        (is_valid, optional_error_message)
    """
    # 1. Null / empty checks
    if not record.timestamp or not str(record.timestamp).strip():
        return False, "Missing or empty timestamp."
    if not record.src_ip or not str(record.src_ip).strip():
        return False, "Missing or empty source IP (src_ip)."
    if not record.dst_ip or not str(record.dst_ip).strip():
        return False, "Missing or empty destination IP (dst_ip)."
    if not record.requested_server_name or not str(record.requested_server_name).strip():
        return False, "Missing or empty requested_server_name."

    # 2. Label validation (must be 0 or 1)
    if record.label not in (0, 1):
        return False, f"Invalid label '{record.label}': must be strictly 0 (benign) or 1 (exfiltration)."

    # 3. Timestamp parsability
    try:
        parse_timestamp(record.timestamp)
    except Exception as e:
        return False, f"Malformed timestamp '{record.timestamp}': {e}"

    # 4. IP address validation
    if not is_valid_ip(record.src_ip):
        return False, f"Invalid source IP address format: '{record.src_ip}'"
    if not is_valid_ip(record.dst_ip):
        return False, f"Invalid destination IP address format: '{record.dst_ip}'"

    # 5. Normalized domain and RFC syntax validation
    normalized = normalize_domain(record.requested_server_name)
    is_valid, reason = is_valid_fqdn(normalized)
    if not is_valid:
        return False, f"Invalid domain name '{record.requested_server_name}': {reason}"

    return True, None


# Alias for backward compatibility and clean API
validate_record = validate_raw_record


class DatasetValidator:
    """Validates an entire batch of RawRecords and accumulates validation metrics."""

    def __init__(self, check_duplicates: bool = True):
        self.check_duplicates = check_duplicates
        self.report = ValidationReport()
        self.seen_signatures: Set[Tuple[str, str, str, str, int]] = set()

    def process(self, record: RawRecord) -> Tuple[bool, Optional[str]]:
        """Processes and records validation stats for a single record."""
        self.report.total_records += 1

        is_valid, err = validate_raw_record(record)
        if not is_valid:
            self.report.invalid_records += 1
            if err:
                self.report.validation_errors.append(err)
            return False, err

        # Duplicate check across core identification signature
        if self.check_duplicates:
            sig = (
                str(record.timestamp).strip(),
                str(record.src_ip).strip(),
                str(record.dst_ip).strip(),
                str(record.requested_server_name).strip().lower(),
                int(record.label),
            )
            if sig in self.seen_signatures:
                self.report.duplicate_records += 1
                return False, f"Duplicate record detected: {sig}"
            self.seen_signatures.add(sig)

        self.report.valid_records += 1
        self.report.label_distribution[record.label] += 1
        return True, None
