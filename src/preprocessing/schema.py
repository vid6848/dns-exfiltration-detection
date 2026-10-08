"""
CyberTrace Preprocessing Schema & Data Contracts
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

================================================================================
CRITICAL ARCHITECTURAL WARNING / DATA LEAKAGE PREVENTION:
================================================================================
The following fields MUST NEVER be used directly as machine learning (ML) features:

1. `src_ip` / `source_ip`:
   - Risk: The model memorizes compromised client IPs (e.g., 10.0.30.186 vs 10.0.30.164)
     instead of learning exfiltration payload characteristics.
   - Allowed Use: ONLY as a grouping key for client behavioral windows (Rudraksh).

2. `dst_ip` / `destination_ip`:
   - Risk: The model memorizes specific DNS resolver IPs (e.g., 8.8.8.8 vs 10.0.0.2).
   - Allowed Use: Resolvers are infrastructure endpoints; do not feed as a raw ML feature.

3. `timestamp` / `epoch_time`:
   - Risk: Monotonic timestamps or datetime strings create chronological shortcuts
     because benign and attack captures may occur at differing dates or hours.
   - Allowed Use: ONLY for chronological record sorting, computing delta-t (inter-arrival
     intervals), and sliding-window boundary calculations.

4. `requested_server_name` / `domain` / `query`:
   - Risk: High-cardinality raw text strings cause models to memorize specific attacker
     apex domains (e.g., "tunnel-sync.net", "data-relay.info", "exfil-corp.org").
   - Allowed Use: Raw strings are decomposed into structural numeric features by Hero
     (entropy, query length, digit ratio, etc.) and grouped by apex domain by Rudraksh.

5. `source`:
   - Risk: Dataset provenance tag (e.g. "Mendeley..." vs "CyberTrace Synthetic...").
     Using this feature results in 100% artificial target leakage.
   - Allowed Use: Auditability and dataset documentation only. Excluded from all ML inputs.
================================================================================
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set, FrozenSet, Iterable


# Exact set of disallowed raw features that must NEVER enter ML feature sets
DISALLOWED_RAW_ML_FEATURES: FrozenSet[str] = frozenset([
    "src_ip",
    "source_ip",
    "dst_ip",
    "destination_ip",
    "timestamp",
    "raw_timestamp",
    "start_time",
    "end_time",
    "epoch_time",
    "requested_server_name",
    "domain",
    "query",
    "source",
])

# Canonical groupings for data contracts
IDENTIFIER_AND_GROUPING_FIELDS: FrozenSet[str] = frozenset([
    "src_ip",
    "dst_ip",
    "apex_domain",
])

TEMPORAL_ANCHOR_FIELDS: FrozenSet[str] = frozenset([
    "timestamp",
    "epoch_time",
])

METADATA_FIELDS: FrozenSet[str] = frozenset([
    "source",
    "raw_source_file",
])

TARGET_FIELD: str = "label"

# Standard column aliases for input ingestion
COLUMN_ALIASES: Dict[str, str] = {
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "dst_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "requested_server_name": "requested_server_name",
    "domain": "requested_server_name",
    "query": "requested_server_name",
    "timestamp": "timestamp",
    "start_time": "timestamp",
    "query_type": "query_type",
    "label": "label",
    "source": "source",
}

# The agreed standard 10-column contract between Vidhi, Param, and Yash
EXPECTED_DATASET_COLUMNS: List[str] = [
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


class DataLeakageError(ValueError):
    """Raised when a disallowed raw identifier or timestamp is supplied as an ML feature."""
    pass


def verify_ml_feature_safety(feature_names: Iterable[str]) -> None:
    """
    Enforces the architectural safety rule before features are passed to model training.

    Raises:
        DataLeakageError: If any prohibited raw field is included in feature_names.
    """
    feature_set: Set[str] = {f.strip().lower() for f in feature_names}
    violations = feature_set.intersection(DISALLOWED_RAW_ML_FEATURES)
    if violations:
        raise DataLeakageError(
            f"DATA LEAKAGE VIOLATION: Disallowed raw fields detected in proposed ML feature set: {sorted(violations)}.\n"
            f"Rule: 'src_ip', 'dst_ip', 'timestamp' (or 'epoch_time'), 'requested_server_name', "
            f"and 'source' should not be used directly as ML features.\n"
            f"- Use 'src_ip' and 'apex_domain' ONLY as grouping keys for behavioral windows.\n"
            f"- Use 'timestamp' ONLY for relative time intervals (delta-t) and window boundaries.\n"
            f"- Use decomposed structural metrics (entropy, length, digit ratio) instead of raw domain.\n"
            f"- Completely exclude 'source'."
        )


@dataclass
class RawRecord:
    """Represents an unnormalized raw DNS record read from an input CSV."""
    timestamp: str
    src_ip: str
    dst_ip: str
    requested_server_name: str
    label: int
    query_type: str = "A"
    source: str = "Unknown"
    extra_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedRecord:
    """
    Represents a validated, normalized, and parsed DNS record.
    Supplied to Hero (per-query features) and Rudraksh (behavioral features).
    """
    # Identifiers & Grouping Keys (NOT raw ML features!)
    src_ip: str
    dst_ip: str
    
    # Normalized Domain & Decomposed Structure
    requested_server_name: str    # Normalized FQDN (lowercase, no trailing dot)
    apex_domain: str              # Registered/apex domain (eTLD+1) for grouping
    subdomain: str                # Subdomain portion (excluding apex domain)
    tld: str                      # Top-Level Domain (e.g. 'com', 'io', 'internal')
    labels: List[str]             # All dot-separated labels as a list
    label_count: int              # Total count of labels
    longest_label: str            # Longest label string
    longest_label_length: int     # Character length of longest label
    subdomain_length: int         # Total character length of subdomain portion
    
    # Standardized Temporal Anchors (NOT raw ML features!)
    timestamp: str                # Standardized string: YYYY-MM-DD HH:MM:SS.mmm
    epoch_time: float             # UTC epoch seconds for delta-t calculations
    
    # Protocol & Metadata
    query_type: str               # e.g., 'A', 'AAAA', 'TXT'
    label: int                    # 0 = Benign, 1 = Exfiltration
    source: str                   # Provenance tag (Audit only!)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the normalized record to a serializable dictionary."""
        return asdict(self)

    def to_csv_row(self) -> Dict[str, Any]:
        """
        Converts the normalized record to a flat dictionary suitable for CSV export.
        Serializes label lists into dot-delimited strings for storage.
        """
        d = self.to_dict()
        d["labels_joined"] = ".".join(self.labels)
        del d["labels"]
        return d
