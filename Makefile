.PHONY: help setup test verify api web demo docker replay replay-fast

VENV := .venv
PYTHON := $(VENV)/bin/python
UVICORN := $(VENV)/bin/uvicorn

help:
	@echo "CyberTrace Integration Makefile"
	@echo "Targets:"
	@echo "  make setup   - Create virtualenv and install all python + frontend dependencies"
	@echo "  make test    - Run backend pytest and frontend test suites"
	@echo "  make verify  - Run verify_release_models script and frontend build"
	@echo "  make api     - Run FastAPI backend on port 8000"
	@echo "  make web     - Run Vite dashboard dev server on port 3000"
	@echo "  make demo    - Start full integrated stack instructions"
	@echo "  make docker  - Build and run the single deployable container on port 8000"
	@echo "  make replay  - Stream the demo attack CSV into the API (API=http://127.0.0.1:8000)"
	@echo "  make replay-fast - Same office traffic, tunnel sending every 5-30 ms (fast-burst fix demo)"

setup:
	uv venv --python 3.12 $(VENV) || python3 -m venv $(VENV)
	$(PYTHON) -m pip install -r requirements.txt || uv pip install -r requirements.txt
	cd frontend && npm ci

test:
	$(PYTHON) -m pytest -q
	cd frontend && npm test

verify:
	$(PYTHON) -m scripts.verify_release_models
	cd frontend && npm run build

api:
	$(UVICORN) api.main:app --host 127.0.0.1 --port 8000 --reload

web:
	cd frontend && npm run dev

demo:
	@echo "=== CyberTrace End-to-End Demo Setup ==="
	@echo "Terminal 1: make api"
	@echo "Terminal 2: make web"
	@echo "Dashboard:  http://localhost:3000"

API ?= http://127.0.0.1:8000

docker:
	docker build -t cybertrace .
	docker run --rm -p 8000:8000 cybertrace

replay:
	$(PYTHON) -m scripts.dns_sensor --api $(API) --capture-id demo-lab replay --speed 6.0 --max-gap 0.5 data/demo/live_demo_stream.csv

replay-fast:
	$(PYTHON) -m scripts.dns_sensor --api $(API) --capture-id demo-lab-fast replay --speed 6.0 --max-gap 0.5 data/demo/fast_burst_demo_stream.csv
