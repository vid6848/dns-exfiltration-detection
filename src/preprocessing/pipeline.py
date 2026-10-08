"""
End-to-End Preprocessing and Ingestion Pipeline
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

Provides:
- Ingestion of arbitrary benign, synthetic, raw, or uploaded CSV files.
- Resilient column mapping and alias resolution.
- Schema validation, RFC checking, and duplicate prevention.
- Domain normalization and structural label decomposition.
- Precise timestamp standardization and chronological ordering.
- Deterministic merged dataset export for Hero, Rudraksh, and Jaynish.
"""

import argparse
import csv
from pathlib import Path
import sys
from typing import List, Optional, Tuple, Iterator

from .schema import (
    RawRecord,
    NormalizedRecord,
    COLUMN_ALIASES,
    verify_ml_feature_safety,
)
from .normalizer import normalize_domain
from .parser import parse_domain_labels
from .timestamps import parse_timestamp, format_timestamp_standard, to_epoch_seconds, sort_records_chronologically
from .validator import DatasetValidator, ValidationReport


EXPORT_HEADER = [
    "timestamp",
    "epoch_time",
    "src_ip",
    "dst_ip",
    "requested_server_name",
    "apex_domain",
    "subdomain",
    "tld",
    "label_count",
    "longest_label",
    "longest_label_length",
    "subdomain_length",
    "query_type",
    "label",
    "source",
]


class PreprocessingPipeline:
    """
    Main preprocessing pipeline that coordinates loading, validation, normalization,
    parsing, sorting, and export.
    """

    def __init__(self, check_duplicates: bool = True):
        self.validator = DatasetValidator(check_duplicates=check_duplicates)

    def parse_csv_row_to_raw_record(self, row: dict) -> RawRecord:
        """Maps an arbitrary dictionary / CSV row to a standardized RawRecord."""
        # Resolve aliases
        mapped: dict = {}
        for k, v in row.items():
            if k is None:
                continue
            canonical = COLUMN_ALIASES.get(k.strip().lower(), k.strip().lower())
            mapped[canonical] = v.strip() if isinstance(v, str) else v

        # Extract primary fields
        ts = str(mapped.get("timestamp", ""))
        src_ip = str(mapped.get("src_ip", ""))
        dst_ip = str(mapped.get("dst_ip", ""))
        server_name = str(mapped.get("requested_server_name", ""))
        
        # Parse label
        raw_label = mapped.get("label", 0)
        try:
            label = int(float(raw_label))
        except (ValueError, TypeError):
            label = -1

        query_type = str(mapped.get("query_type", "A"))
        source = str(mapped.get("source", "Unknown"))

        return RawRecord(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            requested_server_name=server_name,
            label=label,
            query_type=query_type,
            source=source,
            extra_fields=mapped,
        )

    def load_csv(self, file_path: Path, max_rows: Optional[int] = None) -> Iterator[RawRecord]:
        """Reads a CSV file and yields RawRecord instances."""
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                if max_rows and count >= max_rows:
                    break
                yield self.parse_csv_row_to_raw_record(row)
                count += 1

    def normalize_and_parse_record(self, raw: RawRecord) -> NormalizedRecord:
        """Transforms a validated RawRecord into a fully parsed NormalizedRecord."""
        norm_domain = normalize_domain(raw.requested_server_name)
        comp = parse_domain_labels(norm_domain)
        
        parsed_dt = parse_timestamp(raw.timestamp)
        std_timestamp = format_timestamp_standard(parsed_dt)
        epoch_time = to_epoch_seconds(parsed_dt)

        return NormalizedRecord(
            src_ip=raw.src_ip.strip(),
            dst_ip=raw.dst_ip.strip(),
            requested_server_name=norm_domain,
            apex_domain=comp.apex_domain,
            subdomain=comp.subdomain,
            tld=comp.tld,
            labels=comp.labels,
            label_count=comp.label_count,
            longest_label=comp.longest_label,
            longest_label_length=comp.longest_label_length,
            subdomain_length=comp.subdomain_length,
            timestamp=std_timestamp,
            epoch_time=epoch_time,
            query_type=raw.query_type,
            label=raw.label,
            source=raw.source,
        )

    def process_file(
        self,
        file_path: Path,
        max_rows: Optional[int] = None,
    ) -> List[NormalizedRecord]:
        """Loads, validates, and normalizes records from a single CSV file."""
        normalized: List[NormalizedRecord] = []
        for raw in self.load_csv(file_path, max_rows=max_rows):
            is_valid, _ = self.validator.process(raw)
            if is_valid:
                norm_rec = self.normalize_and_parse_record(raw)
                normalized.append(norm_rec)
        return normalized

    def build_cleaned_dataset(
        self,
        benign_path: Path,
        synthetic_path: Path,
        benign_limit: Optional[int] = None,
        synthetic_limit: Optional[int] = None,
    ) -> Tuple[List[NormalizedRecord], ValidationReport]:
        """
        Merges benign and synthetic datasets into a unified, chronologically sorted dataset.
        Guarantees deterministic ordering and zero missing values.
        """
        records: List[NormalizedRecord] = []

        if benign_path.exists():
            records.extend(self.process_file(benign_path, max_rows=benign_limit))
        else:
            raise FileNotFoundError(f"Benign file not found: {benign_path}")

        if synthetic_path.exists():
            records.extend(self.process_file(synthetic_path, max_rows=synthetic_limit))
        else:
            raise FileNotFoundError(f"Synthetic file not found: {synthetic_path}")

        # Deterministic chronological sort
        sorted_records = sort_records_chronologically(records)
        return sorted_records, self.validator.report

    @staticmethod
    def export_to_csv(records: List[NormalizedRecord], output_path: Path) -> None:
        """Exports normalized records to a CSV file matching the handoff schema."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(EXPORT_HEADER)
            for r in records:
                writer.writerow([
                    r.timestamp,
                    f"{r.epoch_time:.3f}",
                    r.src_ip,
                    r.dst_ip,
                    r.requested_server_name,
                    r.apex_domain,
                    r.subdomain,
                    r.tld,
                    r.label_count,
                    r.longest_label,
                    r.longest_label_length,
                    r.subdomain_length,
                    r.query_type,
                    r.label,
                    r.source,
                ])


def main():
    parser = argparse.ArgumentParser(description="CyberTrace Preprocessing & Normalization Pipeline")
    parser.add_argument("--benign", type=Path, default=Path("data/processed/benign_dns_v0.1.csv"),
                        help="Path to processed benign CSV")
    parser.add_argument("--synthetic", type=Path, default=Path("data/processed/synthetic_exfiltration_v0.1.csv"),
                        help="Path to synthetic exfiltration CSV")
    parser.add_argument("--output", type=Path, default=Path("data/processed/cleaned_unified_v0.1.csv"),
                        help="Path to export the cleaned, chronologically sorted CSV")
    parser.add_argument("--benign-limit", type=int, default=None, help="Limit number of benign rows")
    parser.add_argument("--synthetic-limit", type=int, default=None, help="Limit number of synthetic rows")

    args = parser.parse_args()

    pipeline = PreprocessingPipeline(check_duplicates=True)
    print("=" * 68)
    print("RUNNING CYBERTRACE PREPROCESSING PIPELINE")
    print(f"Benign Source:    {args.benign}")
    print(f"Synthetic Source: {args.synthetic}")
    print(f"Target Output:    {args.output}")
    print("=" * 68)

    records, report = pipeline.build_cleaned_dataset(
        benign_path=args.benign,
        synthetic_path=args.synthetic,
        benign_limit=args.benign_limit,
        synthetic_limit=args.synthetic_limit,
    )

    print(report.summary())

    if records:
        print(f"\nExporting {len(records):,} normalized records to: {args.output}")
        pipeline.export_to_csv(records, args.output)
        print("[SUCCESS] Preprocessing completed and exported successfully.")
    else:
        print("[ERROR] No records were processed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
