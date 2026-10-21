# Single container: FastAPI inference API + built React dashboard on one port.

FROM node:20-alpine AS dashboard
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERTRACE_SERVE_DASHBOARD=1 \
    PORT=8000
WORKDIR /app

COPY requirements-serve.txt requirements-training.txt ./
RUN pip install --no-cache-dir -r requirements-serve.txt

COPY api/ api/
COPY src/ src/
COPY artifacts/fast_burst_v0.1/random_forest.joblib artifacts/fast_burst_v0.1/
COPY evaluation/results/baseline_vs_rf_v2/baseline_vs_rf_metrics.json evaluation/results/baseline_vs_rf_v2/
COPY --from=dashboard /build/dist frontend/dist

RUN useradd --create-home cybertrace
USER cybertrace

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health',timeout=4)"
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]
