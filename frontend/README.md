# CyberTrace DNS Exfiltration Detection Dashboard (Frontend)

React + Vite dashboard for real-time and batch DNS exfiltration detection, powered by the CyberTrace FastAPI backend.

---

## 1. Prerequisites & Environment

- **Node.js**: `v18.0.0` or higher (verified on Node `v24.20.0`).
- **npm**: `v9.0.0` or higher (verified on npm `v11.19.0`).
- **Python Backend**: Python 3.10+ running the FastAPI application.

---

## 2. Setup & Installation

From the project root:

```bash
cd frontend
npm ci
```

*(Alternatively, use `npm install` if not using a clean CI installation).*

---

## 3. Development Workflow

### A. Start the Backend API
In a separate terminal from the repository root:

```bash
# Optional: Set allowed origins for cross-origin setups (defaults to localhost:3000, localhost:5173)
# set CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

### B. Start the Frontend Development Server
From the `frontend/` directory:

```bash
npm run dev
```

The application will be available at:
```text
http://localhost:3000/
```

### C. Run Frontend Tests
From the `frontend/` directory:

```bash
npm test
```

This runs the automated API client test suite using Node.js's native test runner (`node --test`), verifying payload construction, schema validation, and error handling.

### D. Production Build
From the `frontend/` directory:

```bash
npm run build
```

The compiled static assets will be output to `frontend/dist/`. To preview the production bundle locally:

```bash
npm run preview
```

---

## 4. API Configuration & Vite Proxy

### Local Development Proxy
The development server configured in `vite.config.js` runs on port **3000** and automatically proxies the following paths to `http://127.0.0.1:8000`:
- `/predict` $\rightarrow$ `http://127.0.0.1:8000/predict`
- `/analyze` $\rightarrow$ `http://127.0.0.1:8000/analyze`
- `/health`  $\rightarrow$ `http://127.0.0.1:8000/health`

By default, the client uses an empty base URL (`DEFAULT_API_BASE_URL = ''`), routing all API requests through the local Vite proxy to avoid CORS issues.

### Direct API Connections / Standalone Deployments
If the dashboard is served independently (e.g. static hosting on S3/Cloudflare/Nginx), configure the API Base URL:
1. In the UI: Use the **API Endpoint Configuration Bar** at the top of the dashboard to enter the direct FastAPI URL (e.g. `http://127.0.0.1:8000` or `https://api.cybertrace.example.com`).
2. On the Backend: Ensure the backend has `CORS_ORIGINS` configured to include the frontend's origin:
   ```bash
   export CORS_ORIGINS="https://dashboard.cybertrace.example.com,http://localhost:3000"
   ```

---

## 5. Environment Variables

| Variable | Scope | Description | Default |
|---|---|---|---|
| `CORS_ORIGINS` | Backend (`api/main.py`) | Comma-separated list of allowed CORS origins | `http://localhost:3000, http://127.0.0.1:3000, http://localhost:5173, http://127.0.0.1:5173` |

---

## 6. Features & Components

- **Interactive Inference**:
  - `POST /predict`: Single DNS query prediction with preset benign and exfiltration samples.
  - `POST /analyze`: Batch query evaluation with JSON syntax validator and sliding-window temporal accumulation.
- **Operational Metrics**:
  - `GET /health`: Live connection status indicator.
  - Informative empty states for continuous packet capture feeds (`/alerts`, `/statistics`).
- **Research Benchmarks**:
  - Offline visualization of Random Forest vs Statistical Baseline metrics.
  - Feature importance breakdown derived from verified research artifacts.
