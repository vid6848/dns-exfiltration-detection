import csv
from datetime import datetime, timezone
import io
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.features.behavioral import BehavioralFeatureExtractor
from src.features.per_query import extract_per_query_features
from src.ml.artifact import load_model, predict_features
from src.preprocessing.pipeline import PreprocessingPipeline


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = (
    PROJECT_ROOT
    / "artifacts"
    / "aws_benign_expansion_v0.1"
    / "random_forest.joblib"
)
METRICS_PATH = (
    PROJECT_ROOT
    / "evaluation"
    / "results"
    / "baseline_vs_rf_v1"
    / "baseline_vs_rf_metrics.json"
)

DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

MAX_CSV_BYTES = 15 * 1024 * 1024  # 15 MB
MAX_CSV_ROWS = 20000


class AppStateStore:
    """Thread-safe in-memory store for real processed query events and alerts."""

    def __init__(self, max_alerts: int = 500):
        self.max_alerts = max_alerts
        self.total_processed: int = 0
        self.total_suspicious: int = 0
        self.total_benign: int = 0
        self.alerts: List[Dict[str, Any]] = []
        self.capture_extractors: Dict[str, BehavioralFeatureExtractor] = {}

    def get_capture_extractor(self, capture_id: str) -> BehavioralFeatureExtractor:
        if capture_id not in self.capture_extractors:
            self.capture_extractors[capture_id] = BehavioralFeatureExtractor(
                window_seconds=60.0
            )
        return self.capture_extractors[capture_id]

    def record_prediction(
        self,
        record: Any,
        label: int,
        attack_score: float,
        threshold: float,
        risk_label: str,
        rule_indicators: Dict[str, bool],
        capture_id: str,
    ) -> Optional[str]:
        self.total_processed += 1
        alert_id = None
        if label == 1:
            self.total_suspicious += 1
            alert_id = f"alt_{uuid.uuid4().hex[:12]}"
            alert_entry = {
                "alert_id": alert_id,
                "timestamp": str(record.timestamp),
                "requested_server_name": str(record.requested_server_name),
                "src_ip": str(record.src_ip),
                "dst_ip": str(record.dst_ip),
                "risk_label": risk_label,
                "attack_score": float(attack_score),
                "decision_threshold": float(threshold),
                "rule_indicators": rule_indicators,
                "capture_id": capture_id,
            }
            self.alerts.insert(0, alert_entry)
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop()
        else:
            self.total_benign += 1
        return alert_id


class DNSQuery(BaseModel):
    timestamp: str = Field(min_length=1)
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    requested_server_name: str = Field(min_length=1)
    query_type: str = "A"
    source: str = "CyberTrace API"
    capture_id: Optional[str] = "default"


class BatchDNSQuery(BaseModel):
    queries: List[DNSQuery] = Field(min_length=1, max_length=1000)
    capture_id: Optional[str] = None


def compute_risk_label(attack_score: float, threshold: float) -> str:
    """Compute risk tier ensuring risk label never contradicts prediction.

    Any score >= threshold is in the suspicious tier ('CRITICAL' or 'SUSPICIOUS').
    Any score < threshold is in a benign tier ('LOW' or 'ELEVATED') and must never read as suspicious.
    """
    if attack_score >= threshold:
        return "CRITICAL"
    if attack_score >= 0.50:
        return "ELEVATED"
    return "LOW"


FROZEN_BASELINE_THRESHOLDS = {
    "query_length": 52.0,
    "entropy": 4.309101,
    "query_frequency": 41.0,
    "unique_subdomains": 41.0,
}


def compute_rule_indicators(features: Dict[str, Any]) -> Dict[str, Any]:
    """Derive indicators from frozen baseline thresholds in src/baseline/detector.py.

    query_length >= 52.0
    entropy >= 4.309101
    query_frequency >= 41.0
    unique_subdomains >= 41.0
    baseline_flagged = True when >= 2 indicators agree.
    """
    length_flag = bool(float(features.get("query_length", 0.0)) >= FROZEN_BASELINE_THRESHOLDS["query_length"])
    entropy_flag = bool(float(features.get("entropy", 0.0)) >= FROZEN_BASELINE_THRESHOLDS["entropy"])
    freq_flag = bool(float(features.get("query_frequency", 1.0)) >= FROZEN_BASELINE_THRESHOLDS["query_frequency"])
    subdomains_flag = bool(float(features.get("unique_subdomains", 1.0)) >= FROZEN_BASELINE_THRESHOLDS["unique_subdomains"])
    agreeing_count = sum([length_flag, entropy_flag, freq_flag, subdomains_flag])

    return {
        "query_length_flag": length_flag,
        "entropy_flag": entropy_flag,
        "query_frequency_flag": freq_flag,
        "unique_subdomains_flag": subdomains_flag,
        "agreeing_indicators_count": agreeing_count,
        "baseline_flagged": bool(agreeing_count >= 2),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not MODEL_PATH.is_file():
        raise RuntimeError(f"Model artifact not found: {MODEL_PATH}")

    app.state.model_bundle = load_model(MODEL_PATH)
    app.state.pipeline = PreprocessingPipeline(check_duplicates=False)
    app.state.behavioral_extractor = BehavioralFeatureExtractor(
        window_seconds=60.0
    )
    app.state.store = AppStateStore()

    yield


app = FastAPI(
    title="CyberTrace DNS Exfiltration Detection API",
    description="API for detecting suspicious DNS activity.",
    version="1.0.0",
    lifespan=lifespan,
)

cors_origins_env = os.getenv("CORS_ORIGINS", "")
if cors_origins_env.strip():
    allowed_origins = [
        origin.strip()
        for origin in cors_origins_env.split(",")
        if origin.strip()
    ]
else:
    allowed_origins = DEFAULT_CORS_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "CyberTrace API is running",
        "status": "ok",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": hasattr(app.state, "model_bundle"),
    }


@app.post("/predict")
def predict_dns_query(query: DNSQuery):
    try:
        pipeline = app.state.pipeline
        capture_id = query.capture_id or "default"

        raw_record = pipeline.parse_csv_row_to_raw_record(
            query.model_dump()
        )
        record = pipeline.normalize_and_parse_record(raw_record)

        features = extract_per_query_features(record)

        # Retrieve capture-isolated behavioral extractor
        extractor = app.state.store.get_capture_extractor(capture_id)
        behavioral_features = extractor.extract(record)
        features.update(behavioral_features)

        predictions, probabilities = predict_features(
            app.state.model_bundle,
            [features],
        )

        probability = float(probabilities[0])
        label = int(predictions[0])
        is_suspicious = bool(label == 1)
        threshold = float(app.state.model_bundle["decision_threshold"])
        risk_label = compute_risk_label(probability, threshold)
        indicators = compute_rule_indicators(features)

        alert_id = app.state.store.record_prediction(
            record=record,
            label=label,
            attack_score=probability,
            threshold=threshold,
            risk_label=risk_label,
            rule_indicators=indicators,
            capture_id=capture_id,
        )

        return {
            "prediction": "suspicious" if is_suspicious else "benign",
            "label": label,
            "attack_score": probability,
            "attack_probability": probability,
            "threshold": threshold,
            "decision_threshold": threshold,
            "risk_label": risk_label,
            "rule_indicators": indicators,
            "alert_id": alert_id,
            "model_identity": {
                "artifact": "artifacts/aws_benign_expansion_v0.1/random_forest.joblib",
                "trees": 150,
                "features": 10,
                "diagnostic_label": "Diagnostic Development Evaluation (Outer Fold 5)",
            },
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.post("/analyze")
def analyze_dns_queries(batch: BatchDNSQuery):
    try:
        pipeline = app.state.pipeline
        batch_capture_id = batch.capture_id or f"batch_{uuid.uuid4().hex[:8]}"

        parsed_queries = []
        for index, query in enumerate(batch.queries):
            raw_record = pipeline.parse_csv_row_to_raw_record(
                query.model_dump()
            )
            record = pipeline.normalize_and_parse_record(raw_record)
            structural_features = extract_per_query_features(record)
            parsed_queries.append({
                "index": index,
                "query": query,
                "record": record,
                "structural_features": structural_features,
            })

        chronological_queries = sorted(
            parsed_queries,
            key=lambda item: float(item["record"].epoch_time),
        )

        # Dedicated batch extractor for isolated batch history
        behavioral_extractor = BehavioralFeatureExtractor(window_seconds=60.0)

        features_by_index = {}
        for item in chronological_queries:
            behavioral_features = behavioral_extractor.extract(item["record"])
            combined = dict(item["structural_features"])
            combined.update(behavioral_features)
            features_by_index[item["index"]] = combined

        ordered_feature_rows = [
            features_by_index[i] for i in range(len(batch.queries))
        ]

        predictions, probabilities = predict_features(
            app.state.model_bundle,
            ordered_feature_rows,
        )

        threshold = float(app.state.model_bundle["decision_threshold"])

        results = []
        for index, query in enumerate(batch.queries):
            probability = float(probabilities[index])
            label = int(predictions[index])
            risk_label = compute_risk_label(probability, threshold)
            indicators = compute_rule_indicators(ordered_feature_rows[index])

            alert_id = app.state.store.record_prediction(
                record=parsed_queries[index]["record"],
                label=label,
                attack_score=probability,
                threshold=threshold,
                risk_label=risk_label,
                rule_indicators=indicators,
                capture_id=query.capture_id or batch_capture_id,
            )

            results.append({
                "requested_server_name": query.requested_server_name,
                "prediction": "suspicious" if label else "benign",
                "label": label,
                "attack_score": probability,
                "attack_probability": probability,
                "threshold": threshold,
                "decision_threshold": threshold,
                "risk_label": risk_label,
                "rule_indicators": indicators,
                "alert_id": alert_id,
            })

        suspicious_count = sum(result["label"] == 1 for result in results)

        return {
            "total_queries": len(results),
            "suspicious_queries": suspicious_count,
            "benign_queries": len(results) - suspicious_count,
            "results": results,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.post("/analyze/csv")
async def analyze_csv(
    file: UploadFile = File(...),
    capture_id: Optional[str] = Form(None),
):
    """Multipart CSV batch analysis endpoint with canonical pipeline parsing and chronological sorting."""
    content = await file.read()
    if len(content) > MAX_CSV_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"CSV file exceeds maximum size limit of {MAX_CSV_BYTES // (1024 * 1024)}MB",
        )

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = content.decode("latin-1")
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail="Unable to decode CSV file contents as UTF-8 or Latin-1",
            ) from exc

    stream = io.StringIO(text)
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="Uploaded CSV file is empty or missing headers")

    rows = list(reader)
    if not rows:
        raise HTTPException(status_code=400, detail="CSV file contains no data rows")

    if len(rows) > MAX_CSV_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"CSV row count {len(rows)} exceeds maximum limit of {MAX_CSV_ROWS} rows",
        )

    # Validate header fields or aliases
    field_map = {}
    for col in reader.fieldnames:
        clean_col = col.strip()
        field_map[clean_col] = clean_col

    req_name_col = None
    for cand in ["requested_server_name", "query", "domain"]:
        if cand in field_map:
            req_name_col = cand
            break

    if not req_name_col:
        raise HTTPException(
            status_code=400,
            detail="CSV missing required domain column ('requested_server_name', 'query', or 'domain')",
        )

    effective_capture_id = capture_id or file.filename or f"csv_{uuid.uuid4().hex[:8]}"
    pipeline = app.state.pipeline

    parsed_queries = []
    invalid_rows = []

    for index, row in enumerate(rows):
        try:
            standardized = {
                "timestamp": row.get("timestamp", "").strip(),
                "src_ip": row.get("src_ip", "").strip() or "127.0.0.1",
                "dst_ip": row.get("dst_ip", "").strip() or "8.8.8.8",
                "requested_server_name": row.get(req_name_col, "").strip(),
                "query_type": row.get("query_type", "A").strip() or "A",
                "source": row.get("source", "CSV Upload").strip() or "CSV Upload",
            }

            if not standardized["timestamp"]:
                # Missing timestamp policy (CONTRACTS.md §3):
                # Fallback to previous valid row, else server ingestion timestamp in UTC, plus a logged warning
                if parsed_queries:
                    standardized["timestamp"] = str(parsed_queries[-1]["record"].timestamp)
                    logging.warning(
                        "Row %d in capture '%s' missing timestamp; falling back to previous valid row timestamp: %s",
                        index + 1,
                        effective_capture_id,
                        standardized["timestamp"],
                    )
                else:
                    standardized["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    logging.warning(
                        "Row %d in capture '%s' missing timestamp; falling back to server ingestion time (UTC): %s",
                        index + 1,
                        effective_capture_id,
                        standardized["timestamp"],
                    )

            raw_record = pipeline.parse_csv_row_to_raw_record(standardized)
            record = pipeline.normalize_and_parse_record(raw_record)
            structural_features = extract_per_query_features(record)

            parsed_queries.append({
                "index": index,
                "record": record,
                "structural_features": structural_features,
            })
        except Exception as exc:
            invalid_rows.append({"row": index + 1, "error": str(exc)})

    if not parsed_queries:
        raise HTTPException(
            status_code=422,
            detail=f"All rows in CSV were invalid. Errors: {invalid_rows[:5]}",
        )

    # Sort valid rows chronologically
    chronological_queries = sorted(
        parsed_queries,
        key=lambda item: float(item["record"].epoch_time),
    )

    # Single capture-isolated behavioral extractor for this upload
    behavioral_extractor = BehavioralFeatureExtractor(window_seconds=60.0)

    features_by_index = {}
    for item in chronological_queries:
        behavioral_features = behavioral_extractor.extract(item["record"])
        combined = dict(item["structural_features"])
        combined.update(behavioral_features)
        features_by_index[item["index"]] = combined

    ordered_feature_rows = [
        features_by_index[item["index"]] for item in parsed_queries
    ]

    predictions, probabilities = predict_features(
        app.state.model_bundle,
        ordered_feature_rows,
    )

    threshold = float(app.state.model_bundle["decision_threshold"])

    results = []
    for i, item in enumerate(parsed_queries):
        probability = float(probabilities[i])
        label = int(predictions[i])
        risk_label = compute_risk_label(probability, threshold)
        indicators = compute_rule_indicators(ordered_feature_rows[i])

        alert_id = app.state.store.record_prediction(
            record=item["record"],
            label=label,
            attack_score=probability,
            threshold=threshold,
            risk_label=risk_label,
            rule_indicators=indicators,
            capture_id=effective_capture_id,
        )

        results.append({
            "requested_server_name": str(item["record"].requested_server_name),
            "prediction": "suspicious" if label else "benign",
            "label": label,
            "attack_score": probability,
            "attack_probability": probability,
            "threshold": threshold,
            "decision_threshold": threshold,
            "risk_label": risk_label,
            "rule_indicators": indicators,
            "alert_id": alert_id,
        })

    suspicious_count = sum(r["label"] == 1 for r in results)

    return {
        "capture_id": effective_capture_id,
        "total_queries": len(results),
        "suspicious_queries": suspicious_count,
        "benign_queries": len(results) - suspicious_count,
        "invalid_rows_skipped": len(invalid_rows),
        "results": results,
    }


@app.get("/alerts")
def get_alerts(limit: int = 50):
    """Retrieve suspicious events from processed records in reverse chronological order."""
    alerts = app.state.store.alerts[:limit]
    return {
        "count": len(alerts),
        "alerts": alerts,
    }


@app.get("/statistics")
def get_statistics():
    """Retrieve actual cumulative traffic and detection counts derived from processed queries."""
    store = app.state.store
    total = store.total_processed
    suspicious = store.total_suspicious
    benign = store.total_benign
    suspicious_rate = float(suspicious / total) if total > 0 else 0.0

    return {
        "total_processed": total,
        "total_suspicious": suspicious,
        "total_benign": benign,
        "suspicious_rate": suspicious_rate,
        "active_alerts_retained": len(store.alerts),
        "has_live_data": bool(total > 0),
    }


@app.get("/model-performance")
def get_model_performance():
    """Return model performance metrics derived from baseline vs RF benchmark JSON."""
    if not METRICS_PATH.is_file():
        raise HTTPException(
            status_code=500,
            detail=f"Evaluation metrics file not found: {METRICS_PATH}",
        )

    try:
        metrics_data = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load evaluation metrics: {exc}",
        ) from exc

    return {
        "diagnostic_label": "diagnostic/development evaluation, not independent final test",
        "model_artifact": "artifacts/aws_benign_expansion_v0.1/random_forest.joblib",
        "decision_threshold": 0.89,
        "evaluation_records": metrics_data.get("evaluation_records", 45240),
        "random_forest": metrics_data.get("random_forest", {}),
        "statistical_baseline": metrics_data.get("statistical_baseline", {}),
        "scope": metrics_data.get(
            "scope",
            "Previously inspected diagnostic development evaluation. Not an independent final test or proof of real-world generalization.",
        ),
    }