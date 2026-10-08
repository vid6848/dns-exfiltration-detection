"""
CyberTrace Preprocessing and Parsing Module
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

Downstream Handoff Contracts:
- Hero: Per-Query Feature Extraction (entropy, query length, label counts, character ratios)
- Rudraksh: Behavioral Features & Statistical Baseline (sliding windows, rates, intervals)
- Jaynish: Supervised Random Forest Training
- Pranay: FastAPI Inference Pipeline

CRITICAL LEAKAGE WARNING:
-------------------------
The following raw fields MUST NOT be used directly as ML features:
- `src_ip` / `source_ip`: IP memorization shortcut. Use ONLY as a grouping key for temporal client windows.
- `dst_ip` / `destination_ip`: Resolver memorization shortcut.
- `timestamp` / `epoch_time`: Raw date/time leakage. Use ONLY for chronological ordering and delta-t / window math.
- `requested_server_name` / `domain`: Raw string memorization shortcut. Use ONLY for structural extraction (Hero) and apex domain grouping (Rudraksh).
- `source`: Dataset provenance tag (100% target leakage). Audit only.
"""

from .schema import (
    DISALLOWED_RAW_ML_FEATURES,
    IDENTIFIER_AND_GROUPING_FIELDS,
    TEMPORAL_ANCHOR_FIELDS,
    METADATA_FIELDS,
    TARGET_FIELD,
    RawRecord,
    NormalizedRecord,
    DataLeakageError,
    verify_ml_feature_safety,
)
from .normalizer import normalize_domain, is_valid_fqdn
from .parser import parse_domain_labels, DomainComponents
from .timestamps import parse_timestamp, format_timestamp_standard, to_epoch_seconds
from .validator import validate_record, DatasetValidator, ValidationReport
from .pipeline import PreprocessingPipeline

__all__ = [
    "DISALLOWED_RAW_ML_FEATURES",
    "IDENTIFIER_AND_GROUPING_FIELDS",
    "TEMPORAL_ANCHOR_FIELDS",
    "METADATA_FIELDS",
    "TARGET_FIELD",
    "RawRecord",
    "NormalizedRecord",
    "DataLeakageError",
    "verify_ml_feature_safety",
    "normalize_domain",
    "is_valid_fqdn",
    "parse_domain_labels",
    "DomainComponents",
    "parse_timestamp",
    "format_timestamp_standard",
    "to_epoch_seconds",
    "validate_record",
    "DatasetValidator",
    "ValidationReport",
    "PreprocessingPipeline",
]
