/**
 * API client for CyberTrace DNS Exfiltration Detection API (FastAPI)
 * Implements the authoritative API contract defined in docs/CONTRACTS.md:
 * - POST /predict: Single DNSQuery -> { prediction, label, attack_score, threshold, risk_label, ... }
 * - POST /analyze: BatchDNSQuery -> { total_queries, suspicious_queries, benign_queries, results: [...] }
 * - POST /analyze/csv: Multipart CSV file upload -> { capture_id, total_queries, suspicious_queries, results: [...] }
 * - GET  /alerts: List of suspicious events from processed queries -> { count, alerts: [...] }
 * - GET  /statistics: Real cumulative telemetry counts -> { total_processed, total_suspicious, total_benign, ... }
 * - GET  /model-performance: Diagnostic model metrics -> { random_forest, statistical_baseline, decision_threshold, ... }
 * - GET  /health: Health status -> { status, model_loaded }
 */

export const DEFAULT_API_BASE_URL = '';

export function buildEndpointUrl(path, baseUrl = DEFAULT_API_BASE_URL) {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  if (!baseUrl || !baseUrl.trim()) {
    return cleanPath;
  }
  return `${baseUrl.trim().replace(/\/$/, '')}${cleanPath}`;
}

export function formatErrorMessage(error, endpoint) {
  if (error instanceof TypeError && error.message.includes('fetch')) {
    return `Failed to connect to API endpoint (${endpoint}). Ensure the FastAPI server is running on http://127.0.0.1:8000.`;
  }
  return error.message || 'Unknown network error';
}

export async function checkApiHealth(baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl('/health', baseUrl);
  try {
    const res = await fetch(url, { method: 'GET' });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}

export async function predictSingleQuery(query, baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl('/predict', baseUrl);

  const payload = {
    timestamp: query.timestamp?.trim() || '',
    src_ip: query.src_ip?.trim() || '',
    dst_ip: query.dst_ip?.trim() || '',
    requested_server_name: query.requested_server_name?.trim() || '',
    query_type: query.query_type?.trim() || 'A',
    source: query.source?.trim() || 'CyberTrace Dashboard',
    capture_id: query.capture_id?.trim() || 'default',
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      let detailMsg = `HTTP ${res.status} ${res.statusText}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) {
          detailMsg = typeof errJson.detail === 'string'
            ? errJson.detail
            : JSON.stringify(errJson.detail);
        }
      } catch {
        // Non-JSON response
      }
      throw new Error(detailMsg);
    }

    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}

export async function analyzeBatchQueries(queries, baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl('/analyze', baseUrl);

  const payload = {
    queries: queries.map((q) => ({
      timestamp: q.timestamp?.trim() || '',
      src_ip: q.src_ip?.trim() || '',
      dst_ip: q.dst_ip?.trim() || '',
      requested_server_name: q.requested_server_name?.trim() || '',
      query_type: q.query_type?.trim() || 'A',
      source: q.source?.trim() || 'CyberTrace Dashboard',
      capture_id: q.capture_id?.trim() || undefined,
    })),
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      let detailMsg = `HTTP ${res.status} ${res.statusText}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) {
          detailMsg = typeof errJson.detail === 'string'
            ? errJson.detail
            : JSON.stringify(errJson.detail);
        }
      } catch {
        // Non-JSON response
      }
      throw new Error(detailMsg);
    }

    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}

export async function analyzeCsvFile(file, captureId = '', baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl('/analyze/csv', baseUrl);
  const formData = new FormData();
  formData.append('file', file);
  if (captureId && captureId.trim()) {
    formData.append('capture_id', captureId.trim());
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      let detailMsg = `HTTP ${res.status} ${res.statusText}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) {
          detailMsg = typeof errJson.detail === 'string'
            ? errJson.detail
            : JSON.stringify(errJson.detail);
        }
      } catch {
        // Non-JSON response
      }
      throw new Error(detailMsg);
    }

    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}

export async function fetchLiveAlerts(limit = 50, baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl(`/alerts?limit=${limit}`, baseUrl);
  try {
    const res = await fetch(url, { method: 'GET' });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}

export async function fetchLiveStatistics(baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl('/statistics', baseUrl);
  try {
    const res = await fetch(url, { method: 'GET' });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}

export async function fetchModelPerformance(baseUrl = DEFAULT_API_BASE_URL) {
  const url = buildEndpointUrl('/model-performance', baseUrl);
  try {
    const res = await fetch(url, { method: 'GET' });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    throw new Error(formatErrorMessage(err, url));
  }
}
