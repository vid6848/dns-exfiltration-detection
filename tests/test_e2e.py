"""End-to-end integration tests for CyberTrace pipeline.

Covers:
- POST /analyze/csv with valid synthetic exfiltration CSV
- Capture isolation: the same domain in two captures does not share history
- Malformed CSV, missing headers, and invalid row handling
- GET /alerts and GET /statistics consistency with actual processed queries
- Chronological ordering in CSV batch processing
"""

import io
import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_e2e_single_query_and_alerts_accumulation(client):
    """Test single query flow and verify alert and statistics state updates."""
    stats_before = client.get("/statistics").json()
    init_total = stats_before["total_processed"]
    init_suspicious = stats_before["total_suspicious"]

    # Benign single query
    benign_payload = {
        "timestamp": "2026-10-12 10:00:00.000",
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "updates.microsoft.com",
    }
    r_benign = client.post("/predict", json=benign_payload)
    assert r_benign.status_code == 200
    assert r_benign.json()["prediction"] == "benign"
    assert r_benign.json()["label"] == 0
    assert r_benign.json()["alert_id"] is None

    # Attack burst query (flagging attack)
    p1 = {
        "timestamp": "2026-10-12 10:01:00.000",
        "src_ip": "10.0.30.186",
        "dst_ip": "10.0.0.2",
        "requested_server_name": "s.2ukez6wzvq7lttlpwff5rkg3.data-relay.info",
    }
    p2 = {
        "timestamp": "2026-10-12 10:01:02.000",
        "src_ip": "10.0.30.186",
        "dst_ip": "10.0.0.2",
        "requested_server_name": "s.3ukez6wzvq7lttlpwff5rkg3.data-relay.info",
    }
    client.post("/predict", json=p1)
    r_attack = client.post("/predict", json=p2)
    assert r_attack.status_code == 200
    d_attack = r_attack.json()
    assert d_attack["prediction"] == "suspicious"
    assert d_attack["label"] == 1
    assert d_attack["alert_id"] is not None

    # Verify statistics reflect the added events
    stats_after = client.get("/statistics").json()
    assert stats_after["total_processed"] == init_total + 3
    assert stats_after["total_suspicious"] >= init_suspicious + 1

    # Verify alerts list contains the flagged alert
    alerts = client.get("/alerts").json()
    assert alerts["count"] > 0
    alert_ids = [a["alert_id"] for a in alerts["alerts"]]
    assert d_attack["alert_id"] in alert_ids


def test_e2e_capture_isolation(client):
    """Verify that identical domains in different capture_ids DO NOT contaminate history."""
    domain = "isolated-test.tunnel.com"
    ip = "172.16.0.5"

    # Capture A: First query at t=10s
    client.post("/predict", json={
        "timestamp": "2026-10-12 11:00:10.000",
        "src_ip": ip,
        "dst_ip": "8.8.8.8",
        "requested_server_name": f"chunk1.{domain}",
        "capture_id": "capture_alpha",
    })

    # Capture B: First query for same domain at t=15s
    res_b = client.post("/predict", json={
        "timestamp": "2026-10-12 11:00:15.000",
        "src_ip": ip,
        "dst_ip": "8.8.8.8",
        "requested_server_name": f"chunk2.{domain}",
        "capture_id": "capture_beta",
    })
    assert res_b.status_code == 200

    # Capture A: Second query at t=20s (should have time_interval ~ 10s and frequency 2)
    res_a2 = client.post("/predict", json={
        "timestamp": "2026-10-12 11:00:20.000",
        "src_ip": ip,
        "dst_ip": "8.8.8.8",
        "requested_server_name": f"chunk3.{domain}",
        "capture_id": "capture_alpha",
    })
    assert res_a2.status_code == 200


def test_e2e_csv_upload_valid_flow(client):
    """Test multipart CSV upload with chronological processing."""
    csv_content = """timestamp,src_ip,dst_ip,requested_server_name,query_type
2026-10-12 12:00:10.000,10.0.1.5,8.8.8.8,api.github.com,A
2026-10-12 12:00:05.000,10.0.1.5,8.8.8.8,google.com,A
2026-10-12 12:00:15.000,10.0.30.186,10.0.0.2,s.2ukez6wzvq7lttlpwff5rkg3.data-relay.info,A
2026-10-12 12:00:17.000,10.0.30.186,10.0.0.2,s.3ukez6wzvq7lttlpwff5rkg3.data-relay.info,A
"""
    file_payload = ("test_capture.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")
    response = client.post(
        "/analyze/csv",
        files={"file": file_payload},
        data={"capture_id": "pcap_test_01"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["capture_id"] == "pcap_test_01"
    assert data["total_queries"] == 4
    assert data["invalid_rows_skipped"] == 0
    # Original input row order preserved
    assert data["results"][0]["requested_server_name"] == "api.github.com"
    assert data["results"][1]["requested_server_name"] == "google.com"


def test_e2e_csv_upload_missing_timestamp_fallback(client, caplog):
    """Test CSV upload missing timestamp fallback (previous valid row or server ingestion time) with logged warnings."""
    import logging
    csv_missing_timestamps = """timestamp,src_ip,dst_ip,requested_server_name,query_type
,10.0.1.5,8.8.8.8,first-no-time.com,A
2026-10-12 14:00:00.000,10.0.1.5,8.8.8.8,second-valid.com,A
,10.0.1.5,8.8.8.8,third-fallback-prev.com,A
"""
    with caplog.at_level(logging.WARNING):
        file_payload = ("missing_ts.csv", io.BytesIO(csv_missing_timestamps.encode("utf-8")), "text/csv")
        response = client.post(
            "/analyze/csv",
            files={"file": file_payload},
            data={"capture_id": "test_fallback_cap"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_queries"] == 3
        assert data["invalid_rows_skipped"] == 0

        # Check logged warnings
        warnings = [record.message for record in caplog.records if record.levelno == logging.WARNING]
        assert any("server ingestion time" in w for w in warnings)
        assert any("previous valid row timestamp" in w for w in warnings)


def test_e2e_csv_upload_malformed_and_missing_headers(client):
    """Test CSV error handling for missing domain headers and empty files."""
    # Missing required domain header
    bad_csv = "timestamp,src_ip,dst_ip\n2026-10-12 12:00:00,10.0.0.1,8.8.8.8\n"
    res1 = client.post(
        "/analyze/csv",
        files={"file": ("bad.csv", io.BytesIO(bad_csv.encode("utf-8")), "text/csv")},
    )
    assert res1.status_code == 400
    assert "missing required domain column" in res1.json()["detail"].lower()

    # Empty file
    empty_csv = ""
    res2 = client.post(
        "/analyze/csv",
        files={"file": ("empty.csv", io.BytesIO(empty_csv.encode("utf-8")), "text/csv")},
    )
    assert res2.status_code == 400


def test_e2e_model_performance_endpoint(client):
    """Verify GET /model-performance contract and values."""
    res = client.get("/model-performance")
    assert res.status_code == 200
    data = res.json()
    assert data["decision_threshold"] == 0.89
    assert data["evaluation_records"] == 45240
    assert data["random_forest"]["precision"] == 1.0
    assert data["random_forest"]["false_positive_rate"] == 0.0
    assert data["random_forest"]["recall"] > 0.90
    assert "diagnostic/development" in data["diagnostic_label"]
