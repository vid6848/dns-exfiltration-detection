
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List

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


class DNSQuery(BaseModel):
    timestamp: str = Field(min_length=1)
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    requested_server_name: str = Field(min_length=1)
    query_type: str = "A"
    source: str = "CyberTrace API"

class BatchDNSQuery(BaseModel):
    queries: List[DNSQuery] = Field(min_length=1, max_length=1000)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not MODEL_PATH.is_file():
        raise RuntimeError(f"Model artifact not found: {MODEL_PATH}")

    # Load the trusted model bundle once at startup.
    app.state.model_bundle = load_model(MODEL_PATH)
    app.state.pipeline = PreprocessingPipeline(check_duplicates=False)
    app.state.behavioral_extractor = BehavioralFeatureExtractor(
        window_seconds=60.0
    )

    yield


app = FastAPI(
    title="CyberTrace DNS Exfiltration Detection API",
    description="API for detecting suspicious DNS activity.",
    version="1.0.0",
    lifespan=lifespan,
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

        # Convert the request into the project's existing record format.
        raw_record = pipeline.parse_csv_row_to_raw_record(
            query.model_dump()
        )
        record = pipeline.normalize_and_parse_record(raw_record)

        # Generate the seven structural features.
        features = extract_per_query_features(record)

        # Generate the three behavioural features.
        behavioral_features = (
            app.state.behavioral_extractor.extract(record)
        )
        features.update(behavioral_features)

        # Use the saved feature order and decision threshold.
        predictions, probabilities = predict_features(
            app.state.model_bundle,
            [features],
        )

        probability = float(probabilities[0])
        is_suspicious = bool(predictions[0])

        return {
            "prediction": (
                "suspicious" if is_suspicious else "benign"
            ),
            "label": int(predictions[0]),
            "attack_probability": probability,
            "decision_threshold": float(
                app.state.model_bundle["decision_threshold"]
            ),
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
        feature_rows = []

        # Process each query independently.
        for query in batch.queries:
            raw_record = pipeline.parse_csv_row_to_raw_record(
                query.model_dump()
            )
            record = pipeline.normalize_and_parse_record(raw_record)

            # Structural features for this query.
            features = extract_per_query_features(record)

            # Fresh behavioral context for this query.
            behavioral_extractor = BehavioralFeatureExtractor(
                window_seconds=60.0
            )
            behavioral_features = behavioral_extractor.extract(record)
            features.update(behavioral_features)

            feature_rows.append(features)

        # Predict all independently constructed feature rows.
        predictions, probabilities = predict_features(
            app.state.model_bundle,
            feature_rows,
        )

        threshold = float(
            app.state.model_bundle["decision_threshold"]
        )

        results = []
        for index, query in enumerate(batch.queries):
            probability = float(probabilities[index])
            label = int(predictions[index])

            results.append({
                "requested_server_name": query.requested_server_name,
                "prediction": "suspicious" if label else "benign",
                "label": label,
                "attack_probability": probability,
                "decision_threshold": threshold,
            })

        suspicious_count = sum(
            result["label"] == 1 for result in results
        )

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