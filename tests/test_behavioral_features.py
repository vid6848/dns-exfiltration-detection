import csv
from pathlib import Path

import pytest

from src.features.behavioral import (
    BEHAVIORAL_FEATURE_NAMES,
    BehavioralFeatureExtractor,
    extract_behavioral_features,
)
from src.features.generate_features_csv import generate_features_csv
from src.preprocessing.schema import NormalizedRecord, verify_ml_feature_safety


def make_record(epoch_time, subdomain, src_ip="10.0.0.1", apex_domain="example.com"):
    return NormalizedRecord(
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        requested_server_name=f"{subdomain}.{apex_domain}" if subdomain else apex_domain,
        apex_domain=apex_domain,
        subdomain=subdomain,
        tld="com",
        labels=[],
        label_count=2,
        longest_label="example",
        longest_label_length=7,
        subdomain_length=len(subdomain),
        timestamp="2025-01-01 00:00:00.000",
        epoch_time=float(epoch_time),
        query_type="A",
        label=0,
        source="test",
    )


def test_sliding_window_frequency_and_unique_subdomains():
    records = [
        make_record(0, "one"),
        make_record(30, "two"),
        make_record(60, "one"),  # The 0-second query remains at the inclusive boundary.
        make_record(61, "three"),  # The 0-second query expires.
    ]

    features = extract_behavioral_features(records, window_seconds=60)

    assert [feature["query_frequency"] for feature in features] == [1, 2, 3, 3]
    assert [feature["unique_subdomains"] for feature in features] == [1, 2, 2, 3]


def test_time_interval_is_per_group_and_first_query_uses_sentinel():
    records = [
        make_record(10, "one"),
        make_record(12, "other", apex_domain="other.com"),
        make_record(17.5, "two"),
        make_record(20, "three", src_ip="10.0.0.2"),
    ]

    features = extract_behavioral_features(records)

    assert [feature["time_interval"] for feature in features] == [-1.0, -1.0, 7.5, -1.0]


def test_rejects_non_chronological_records_within_a_group():
    extractor = BehavioralFeatureExtractor()
    extractor.extract(make_record(10, "one"))
    with pytest.raises(ValueError, match="chronological"):
        extractor.extract(make_record(9, "two"))


def test_window_duration_must_be_positive():
    with pytest.raises(ValueError, match="greater than zero"):
        BehavioralFeatureExtractor(0)


def test_behavioral_feature_names_are_safe_ml_features():
    verify_ml_feature_safety(BEHAVIORAL_FEATURE_NAMES)


def test_generator_processes_the_actual_cleaned_dataset():
    input_csv = Path("data/processed/cleaned_unified_v0.1.csv")
    output_csv = Path("data/processed/.test_behavioral_features_output.csv")

    try:
        row_count = generate_features_csv(input_csv, output_csv, window_seconds=60)

        with output_csv.open(encoding="utf-8", newline="") as output_file:
            reader = csv.DictReader(output_file)
            first_row = next(reader)
            second_row = next(reader)

        assert row_count > 0
        assert set(BEHAVIORAL_FEATURE_NAMES).issubset(first_row)
        assert first_row["query_frequency"] == "1"
        assert first_row["unique_subdomains"] == "1"
        assert first_row["time_interval"] == "-1.0"
        assert float(second_row["query_frequency"]) >= 1
    finally:
        output_csv.unlink(missing_ok=True)
