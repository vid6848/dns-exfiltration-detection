# CyberTrace End-to-End Demonstration Guide

**Author:** Soham (Project Coordination & Integration, `soham.prajapati24@spit.ac.in`)  
**Date:** 2026-10-13  
**Audience:** CNS Course Evaluators & Team Members  

---

## 1. Overview

This document provides a step-by-step, 100% reproducible walkthrough of the integrated CyberTrace DNS Exfiltration Detection stack:
1. Environment setup and test suite verification.
2. Starting the FastAPI backend service (`http://127.0.0.1:8000`).
3. Starting the React / Vite dashboard (`http://localhost:3000`).
4. Evaluating single benign and attack queries.
5. Ingesting and evaluating a batch CSV file with chronological sorting and capture isolation.
6. Reviewing real live alerts, statistics telemetry, and model performance benchmarks.

---

## 2. Step 1: Fresh Clone & Setup

```bash
# 1. Clone repository
git clone https://github.com/vid6848/dns-exfiltration-detection.git
cd dns-exfiltration-detection
git checkout integration/soham-e2e

# 2. Automated setup using Makefile (or manually via pip/npm)
make setup

# Alternatively, manual steps:
# python3 -m venv .venv
# source .venv/bin/activate
# pip install -r requirements.txt
# cd frontend && npm ci && cd ..
```

---

## 3. Step 2: Verification of Test Suites & Model Reproduction

Before launching the web services, verify the automated regression suite:

```bash
# Run full backend test suite (89 passed tests)
python -m pytest -q

# Expected Output:
# 89 passed, 1 warning, 13 subtests passed in ~6.6s

# Verify exact probability reproduction across release models
python -m scripts.verify_release_models

# Expected Output:
# random_forest_v0.1: all 38,155 saved probabilities and predictions reproduced exactly
# aws_benign_expansion_v0.1: all 45,240 saved probabilities and predictions reproduced exactly

# Verify frontend test suite and production build
cd frontend && npm test && npm run build && cd ..

# Expected Output:
# 8 passed tests (100% pass)
# vite build succeeded
```

---

## 4. Step 3: Running the Full Stack

Open two terminal windows:

### Terminal 1: FastAPI Backend
```bash
make api
# Or directly:
# .venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```
*Expected Output:*
```text
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Terminal 2: React Dashboard
```bash
make web
# Or directly:
# cd frontend && npm run dev
```
*Expected Output:*
```text
  VITE v6.4.4  ready in 200 ms

  ➜  Local:   http://localhost:3000/
```

Open `http://localhost:3000` in your web browser. The status bar at the top will indicate **System Online: All endpoints healthy & model bundle loaded**.

---

## 5. Step 4: End-to-End Walkthrough Scenarios

### Scenario A: Benign Single Query Prediction
1. In the **Single Query Inference** card, click **Quick Presets -> Benign Sample**.
   - Timestamp: Current UTC timestamp
   - Source IP: `192.168.1.105`
   - Destination IP: `8.8.8.8`
   - Requested Server Name: `api.github.com`
2. Click **Run Query Inference (/predict)**.
3. **Observed Result:**
   - Prediction badge: `✅ BENIGN`
   - Attack Score: `< 1.0%` (0.0001)
   - Decision Threshold: `0.8900`
   - Risk Level: `LOW`
   - Alert Generated: `None`

### Scenario B: Simulated Exfiltration Attack Prediction
1. Click **Quick Presets -> Encoded-Domain Example** or enter:
   - Requested Server Name: `s.2ukez6wzvq7lttlpwff5rkg3.data-relay.info`
   - Source IP: `10.0.30.186`
   - Destination IP: `10.0.0.2`
2. Submit the query twice in succession to emulate burst tunneling.
3. **Observed Result:**
   - Prediction badge: `🚨 SUSPICIOUS`
   - Attack Score: `> 89.0%` (e.g. `94.2%`)
   - Decision Threshold: `0.8900`
   - Risk Level: `CRITICAL`
   - Alert ID: `alt_xxxx...` generated.
   - **Live Alert Feed**: The alert dynamically appears at the top of the **Suspicious DNS Activity** feed table with highlighted indicators (`Entropy ≥ 4.0`, `Subdomain ≥ 25`).
   - **Live Traffic Overview**: Increments `Total DNS Queries` and `Suspicious Queries`.

### Scenario C: CSV File Batch Upload
1. In the **Batch Query Analysis** card, click the **CSV File Upload (/analyze/csv)** tab.
2. Create or select a sample CSV file (e.g., `data/processed/synthetic_dev_sample_100.csv`).
3. Click **Upload & Analyze CSV**.
4. **Observed Result:**
   - Displays total queries processed (e.g. 100), suspicious count, and benign count.
   - Table displays itemized predictions, attack scores, and risk badges.
   - The **Traffic Analysis Stream** bar updates to show the live distribution of clean vs flagged queries.

### Scenario D: Live Telemetry & Model Performance Verification
1. Scroll to the **Suspicious DNS Activity** feed:
   - Shows real flagged alerts with timestamps, client IPs, and trigger indicators.
2. Scroll to the **Model Evaluation & Benchmark Performance** section:
   - Fetches live from `GET /model-performance`.
   - Explicitly displays the diagnostic disclaimer: `"diagnostic/development evaluation, not independent final test"`.
   - Confirms Random Forest precision = 100.0%, FPR = 0.00%, recall = 90.53% at threshold 0.89 on 45,240 records.

---

## 6. Known Limitations & Caveats

1. **Diagnostic Population Scope:** Metrics reflect evaluation on the 45,240 development records (including AWS EC2 benign domains); real-world production generalization requires independent untouched enterprise traffic.
2. **Encrypted DNS (DoH/DoT):** CyberTrace operates on unencrypted DNS queries where hostnames are visible in packet headers; full DoH payloads require endpoint instrumentation or SNI inspection.
3. **In-Memory Telemetry Persistence:** The reference API stores active alerts in an in-memory ring buffer (up to 500 events) for demonstration speed and security; enterprise deployment would attach a Redis or PostgreSQL time-series store.
