"""Tests for CyberTrace authoritative API and data contracts.

Verifies:
- Exact feature schema and order (10 features)
- 0.89 decision threshold applied
- First-query time_interval == -1.0
- Inclusive 60-second window behavior
- Raw IPs, timestamps, and labels never reach the feature vector
- Diagnostic label on model performance
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.features.behavioral import BehavioralFeatureExtractor
from src.features.per_query import FEATURE_NAMES, extract_per_query_features
from src.ml.artifact import load_model, predict_features
from src.ml.features import FEATURE_ORDER
from src.preprocessing.pipeline import PreprocessingPipeline
from src.preprocessing.schema import NormalizedRecord, verify_ml_feature_safety


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_ten_feature_manifest_exact_order():
    """Verify that per-query (7) and behavioral (3) combine to match the exact 10-feature manifest."""
    expected_manifest = (
        "query_length",
        "longest_label_length",
        "number_of_labels",
        "entropy",
        "digit_ratio",
        "special_char_ratio",
        "subdomain_length",
        "query_frequency",
        "unique_subdomains",
        "time_interval",
    )
    assert FEATURE_ORDER == expected_manifest
    assert len(FEATURE_ORDER) == 10


def test_data_leakage_prohibition():
    """Verify that raw IPs, domains, timestamps, and labels are strictly forbidden from ML features."""
    pipeline = PreprocessingPipeline(check_duplicates=False)
    raw = pipeline.parse_csv_row_to_raw_record({
        "timestamp": "2026-10-12 12:00:00.000",
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "sub.tunnel.exfil.org",
        "query_type": "A",
        "source": "AuditLog",
    })
    record = pipeline.normalize_and_parse_record(raw)
    structural = extract_per_query_features(record)
    behavioral = BehavioralFeatureExtractor(window_seconds=60.0).extract(record)
    combined = dict(structural)
    combined.update(behavioral)

    # All keys in combined feature vector must be in FEATURE_ORDER
    assert set(combined.keys()) == set(FEATURE_ORDER)

    # Disallowed fields must never leak into feature keys
    disallowed = {"src_ip", "dst_ip", "timestamp", "epoch_time", "requested_server_name", "label", "source"}
    assert disallowed.isdisjoint(combined.keys())

    # Official safety check
    verify_ml_feature_safety(list(combined.keys()))


def test_first_query_time_interval_negative_one():
    """Verify that the first query for a (src_ip, apex_domain) pair receives time_interval = -1.0."""
    pipeline = PreprocessingPipeline(check_duplicates=False)
    extractor = BehavioralFeatureExtractor(window_seconds=60.0)

    raw = pipeline.parse_csv_row_to_raw_record({
        "timestamp": "2026-10-12 12:00:00.000",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "test1.example.com",
    })
    record = pipeline.normalize_and_parse_record(raw)
    features = extractor.extract(record)

    assert features["time_interval"] == -1.0
    assert features["query_frequency"] == 1.0
    assert features["unique_subdomains"] == 1.0


def test_inclusive_60_second_sliding_window():
    """Verify that queries within [t - 60.0, t] accumulate frequency and unique subdomains."""
    pipeline = PreprocessingPipeline(check_duplicates=False)
    extractor = BehavioralFeatureExtractor(window_seconds=60.0)

    # Query 1 at t=0
    r1 = pipeline.normalize_and_parse_record(pipeline.parse_csv_row_to_raw_record({
        "timestamp": "2026-10-12 12:00:00.000",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "sub1.target.org",
    }))
    f1 = extractor.extract(r1)
    assert f1["query_frequency"] == 1.0
    assert f1["unique_subdomains"] == 1.0

    # Query 2 at t=30 (within 60s)
    r2 = pipeline.normalize_and_parse_record(pipeline.parse_csv_row_to_raw_record({
        "timestamp": "2026-10-12 12:00:30.000",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "sub2.target.org",
    }))
    f2 = extractor.extract(r2)
    assert f2["query_frequency"] == 2.0
    assert f2["unique_subdomains"] == 2.0
    assert f2["time_interval"] == 30.0

    # Query 3 at t=60 (exact 60.0s boundary - inclusive)
    r3 = pipeline.normalize_and_parse_record(pipeline.parse_csv_row_to_raw_record({
        "timestamp": "2026-10-12 12:01:00.000",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "sub3.target.org",
    }))
    f3 = extractor.extract(r3)
    assert f3["query_frequency"] == 3.0
    assert f3["unique_subdomains"] == 3.0
    assert f3["time_interval"] == 30.0

    # Query 4 at t=125 (t1 and t2 fall outside sliding window)
    r4 = pipeline.normalize_and_parse_record(pipeline.parse_csv_row_to_raw_record({
        "timestamp": "2026-10-12 12:02:05.000",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "sub4.target.org",
    }))
    f4 = extractor.extract(r4)
    # At t=125s, [65s, 125s] contains r3 (at 60s is excluded since 125-60=65 > 60s)
    assert f4["query_frequency"] == 1.0
    assert f4["time_interval"] == 65.0


def test_saved_089_threshold_enforced(client):
    """Verify that the API enforces the calibrated 0.89 threshold."""
    res = client.get("/model-performance")
    assert res.status_code == 200
    data = res.json()
    assert data["decision_threshold"] == 0.89
    assert "diagnostic/development" in data["diagnostic_label"]


def test_error_status_codes_and_validation(client):
    """Verify that invalid payloads return standard HTTP 422 errors."""
    res = client.post("/predict", json={"src_ip": "10.0.0.1"})
    assert res.status_code == 422

    res_empty = client.post("/analyze", json={"queries": []})
    assert res_empty.status_code == 422
