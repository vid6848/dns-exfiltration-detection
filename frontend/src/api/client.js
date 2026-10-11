/**
 * API client for CyberTrace DNS Exfiltration Detection API (FastAPI)
 * Based on Pranay's PR #4 API contract:
 * - POST /predict: Single DNSQuery -> { prediction, label, attack_probability, decision_threshold }
 * - POST /analyze: BatchDNSQuery ({ queries: [...] }) -> { total_queries, suspicious_queries, benign_queries, results: [...] }
 * - GET  /health:  Health status -> { status, model_loaded }
 */

// Default to empty string so requests go through the local Vite dev proxy by default
export const DEFAULT_API_BASE_URL = '';

function buildEndpointUrl(path, baseUrl = DEFAULT_API_BASE_URL) {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  if (!baseUrl || !baseUrl.trim()) {
    return cleanPath;
  }
  return `${baseUrl.trim().replace(/\/$/, '')}${cleanPath}`;
}

function formatErrorMessage(error, endpoint) {
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
      query_type: query_type(q),
      source: q.source?.trim() || 'CyberTrace Dashboard',
    })),
  };

  function query_type(q) {
    return q.query_type?.trim() || 'A';
  }

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
