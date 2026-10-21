import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app, lifespan


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "CyberTrace API is running"
    assert data["status"] == "ok"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True


def test_cors_headers_and_preflight(client):
    # Test preflight OPTIONS request
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type",
    }
    response = client.options("/predict", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "POST" in response.headers.get("access-control-allow-methods", "")

    # Test actual GET with Origin
    get_res = client.get("/", headers={"Origin": "http://localhost:3000"})
    assert get_res.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_predict_benign_query(client):
    payload = {
        "timestamp": "2026-10-12T00:00:00Z",
        "src_ip": "192.168.1.105",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "api.github.com",
        "query_type": "A",
        "source": "CyberTrace Dashboard",
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "benign"
    assert data["label"] == 0
    assert isinstance(data["attack_probability"], float)
    assert data["attack_probability"] < 0.1
    assert data["decision_threshold"] == 0.9


def test_predict_exfiltration_query(client):
    # Domain with high entropy and tunneling pattern from exfiltration dataset
    # In this model, consecutive burst queries elevate query_frequency and attack_probability
    payload1 = {
        "timestamp": "2025-06-13 09:45:58.483",
        "src_ip": "10.0.30.186",
        "dst_ip": "10.0.0.2",
        "requested_server_name": "s.2ukez6wzvq7lttlpwff5rkg3.data-relay.info",
        "query_type": "A",
        "source": "CyberTrace Dashboard",
    }
    payload2 = {
        "timestamp": "2025-06-13 09:46:00.000",
        "src_ip": "10.0.30.186",
        "dst_ip": "10.0.0.2",
        "requested_server_name": "s.3ukez6wzvq7lttlpwff5rkg3.data-relay.info",
        "query_type": "A",
        "source": "CyberTrace Dashboard",
    }
    # Initial query establishes baseline state
    r1 = client.post("/predict", json=payload1)
    assert r1.status_code == 200
    assert r1.json()["attack_probability"] > 0.80

    # Successive query in sliding window elevates behavioral frequency and flags suspicious
    r2 = client.post("/predict", json=payload2)
    assert r2.status_code == 200
    data = r2.json()
    assert data["prediction"] == "suspicious"
    assert data["label"] == 1
    assert data["attack_probability"] >= 0.9
    assert data["decision_threshold"] == 0.9


def test_predict_missing_required_fields(client):
    # Missing requested_server_name
    invalid_payload = {
        "timestamp": "2026-10-12T00:00:00Z",
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
    }
    response = client.post("/predict", json=invalid_payload)
    assert response.status_code == 422


def test_predict_malformed_empty_field(client):
    # Empty requested_server_name (violates min_length=1)
    invalid_payload = {
        "timestamp": "2026-10-12T00:00:00Z",
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "",
    }
    response = client.post("/predict", json=invalid_payload)
    assert response.status_code == 422


def test_analyze_empty_queries(client):
    response = client.post("/analyze", json={"queries": []})
    assert response.status_code == 422


def test_analyze_batch_ordering_and_behavioral_accumulation(client):
    # Send 4 queries:
    # Query 0: 10.0.0.1 -> evil.com at t=10s
    # Query 1: 192.168.1.1 -> benign.com at t=12s (unrelated group)
    # Query 2: 10.0.0.1 -> evil.com at t=15s (related group, frequency should increase)
    # Query 3: 10.0.0.1 -> evil.com at t=5s (out of order in batch, but should sort before t=10s)
    batch_payload = {
        "queries": [
            {
                "timestamp": "2026-10-12 00:00:10.000",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "requested_server_name": "sub1.evil.com",
                "query_type": "TXT",
            },
            {
                "timestamp": "2026-10-12 00:00:12.000",
                "src_ip": "192.168.1.1",
                "dst_ip": "8.8.8.8",
                "requested_server_name": "www.google.com",
                "query_type": "A",
            },
            {
                "timestamp": "2026-10-12 00:00:15.000",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "requested_server_name": "sub2.evil.com",
                "query_type": "TXT",
            },
            {
                "timestamp": "2026-10-12 00:00:05.000",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "requested_server_name": "sub0.evil.com",
                "query_type": "TXT",
            },
        ]
    }

    response = client.post("/analyze", json=batch_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["total_queries"] == 4
    assert len(data["results"]) == 4

    # Verify results preserve original input order
    assert data["results"][0]["requested_server_name"] == "sub1.evil.com"
    assert data["results"][1]["requested_server_name"] == "www.google.com"
    assert data["results"][2]["requested_server_name"] == "sub2.evil.com"
    assert data["results"][3]["requested_server_name"] == "sub0.evil.com"

    assert data["results"][1]["prediction"] == "benign"
    assert data["results"][1]["label"] == 0


def test_analyze_unrelated_queries_do_not_contaminate(client):
    # Two queries from different client IPs to different apex domains
    batch_payload = {
        "queries": [
            {
                "timestamp": "2026-10-12 00:00:10.000",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "requested_server_name": "api.service.com",
                "query_type": "A",
            },
            {
                "timestamp": "2026-10-12 00:00:11.000",
                "src_ip": "10.0.0.2",
                "dst_ip": "8.8.8.8",
                "requested_server_name": "cdn.assets.org",
                "query_type": "A",
            },
        ]
    }

    response = client.post("/analyze", json=batch_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_queries"] == 2
    assert data["results"][0]["requested_server_name"] == "api.service.com"
    assert data["results"][1]["requested_server_name"] == "cdn.assets.org"


def test_lifespan_missing_model_file():
    # Verify that lifespan raises RuntimeError when the model artifact is missing
    with patch("api.main.MODEL_PATH", Path("artifacts/nonexistent_model.joblib")):
        test_app = app
        with pytest.raises(RuntimeError, match="Model artifact not found"):
            with TestClient(test_app):
                pass
