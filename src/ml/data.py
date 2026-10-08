"""Domain-disjoint splits and causal feature extraction inside each partition."""

import csv
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from src.features.behavioral import BehavioralFeatureExtractor
from src.features.per_query import extract_per_query_features
from src.preprocessing.pipeline import PreprocessingPipeline
from src.preprocessing.schema import NormalizedRecord
from src.preprocessing.validator import validate_raw_record
from .features import feature_matrix


@dataclass(frozen=True)
class Example:
    row_id: int  # One-based data-row number in the original input CSV.
    record: NormalizedRecord


def load_records(path: Path):
    """Fail on malformed data; deduplicate normalized events before splitting."""
    pipeline = PreprocessingPipeline(check_duplicates=False)
    records, seen, removed = [], {}, []
    with path.open(encoding="utf-8", newline="") as stream:
        for row_id, row in enumerate(csv.DictReader(stream), start=1):
            try:
                if float(row.get("label", "")) not in (0.0, 1.0):
                    raise ValueError("label must be exactly 0 or 1")
                raw = pipeline.parse_csv_row_to_raw_record(row)
                valid, reason = validate_raw_record(raw)
                if not valid:
                    raise ValueError(reason)
                record = pipeline.normalize_and_parse_record(raw)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid input data row {row_id}: {exc}") from exc
            key = (record.epoch_time, record.src_ip, record.dst_ip,
                   record.requested_server_name, record.query_type)
            if key in seen:
                if seen[key] != record.label:
                    raise ValueError(f"Conflicting labels for duplicate event at row {row_id}")
                removed.append(row_id)
                continue
            seen[key] = record.label
            records.append(Example(row_id, record))
    if not records:
        raise ValueError("Input dataset is empty")
    return records, removed


def split_records(records, seed=42):
    """Five stratified group folds: fold 0 test, fold 1 validation, rest train.

    Apex domain is the group, across ALL clients. Thus a client/domain history
    or attack campaign targeting one apex cannot straddle partitions. Ratios
    are approximate because complete groups must stay together. Labels are
    used only to balance allocation, never to select a split by model scores.
    """
    labels = np.asarray([e.record.label for e in records])
    groups = np.asarray([e.record.apex_domain for e in records])
    for label in (0, 1):
        if len(set(groups[labels == label])) < 5:
            raise ValueError("Each class needs at least five distinct apex domains")
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    partitions = {"train": [], "validation": [], "test": []}
    for fold, (_, indexes) in enumerate(splitter.split(np.zeros(len(records)), labels, groups)):
        name = "test" if fold == 0 else "validation" if fold == 1 else "train"
        partitions[name].extend(records[int(index)] for index in indexes)
    group_sets = {name: {e.record.apex_domain for e in items} for name, items in partitions.items()}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if group_sets[left] & group_sets[right]:
            raise AssertionError("Apex-domain overlap between partitions")
    for name, items in partitions.items():
        if {e.record.label for e in items} != {0, 1}:
            raise ValueError(f"{name} must contain both classes; dataset cannot support this split")
        items.sort(key=lambda e: (e.record.epoch_time, e.row_id))
    return partitions


def derive_features(examples, window_seconds=60.0):
    """Fresh history per split; earlier queries only, plus the current query."""
    extractor = BehavioralFeatureExtractor(window_seconds)
    rows = []
    for example in examples:
        features = extract_per_query_features(example.record)
        features.update(extractor.extract(example.record))
        rows.append(features)
    return rows, feature_matrix(rows), np.asarray([e.record.label for e in examples], dtype=np.int64)
