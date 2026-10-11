import React, { useState } from 'react';
import { analyzeBatchQueries } from '../api/client';

const SAMPLE_BATCH_QUERIES = [
  {
    timestamp: '2026-10-12T00:01:10Z',
    src_ip: '192.168.1.101',
    dst_ip: '8.8.8.8',
    requested_server_name: 'cdn.cloudflare.com',
    query_type: 'A',
  },
  {
    timestamp: '2026-10-12T00:01:15Z',
    src_ip: '192.168.1.102',
    dst_ip: '1.1.1.1',
    requested_server_name: 'updates.microsoft.com',
    query_type: 'A',
  },
  {
    timestamp: '2026-10-12T00:01:20Z',
    src_ip: '10.0.12.55',
    dst_ip: '198.51.100.99',
    requested_server_name: '7861636b65722d646174612d657866696c.c2-exfil-dns.evil-corp.cc',
    query_type: 'TXT',
  },
  {
    timestamp: '2026-10-12T00:01:25Z',
    src_ip: '192.168.1.103',
    dst_ip: '8.8.4.4',
    requested_server_name: 'registry.npmjs.org',
    query_type: 'A',
  },
];

export default function BatchAnalysisForm({ apiBaseUrl }) {
  const [jsonInput, setJsonInput] = useState(
    JSON.stringify({ queries: SAMPLE_BATCH_QUERIES }, null, 2)
  );
  const [loading, setLoading] = useState(false);
  const [validationError, setValidationError] = useState('');
  const [apiError, setApiError] = useState('');
  const [result, setResult] = useState(null);

  const handleLoadSample = () => {
    // Generate fresh timestamps for current run
    const now = new Date();
    const freshQueries = SAMPLE_BATCH_QUERIES.map((q, idx) => ({
      ...q,
      timestamp: new Date(now.getTime() + idx * 2000).toISOString(),
    }));
    setJsonInput(JSON.stringify({ queries: freshQueries }, null, 2));
    setValidationError('');
    setApiError('');
    setResult(null);
  };

  const handleFormatJson = () => {
    try {
      const parsed = JSON.parse(jsonInput);
      setJsonInput(JSON.stringify(parsed, null, 2));
      setValidationError('');
    } catch (err) {
      setValidationError(`Cannot format: invalid JSON syntax (${err.message})`);
    }
  };

  const handleClear = () => {
    setJsonInput('{\n  "queries": []\n}');
    setValidationError('');
    setApiError('');
    setResult(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setValidationError('');
    setApiError('');
    setResult(null);

    // 1. Parse JSON
    let parsedData;
    try {
      parsedData = JSON.parse(jsonInput);
    } catch (err) {
      setValidationError(`Invalid JSON syntax: ${err.message}`);
      return;
    }

    // 2. Validate payload structure: must be { queries: [...] } or direct [...] array
    let queryList;
    if (Array.isArray(parsedData)) {
      queryList = parsedData;
    } else if (parsedData && Array.isArray(parsedData.queries)) {
      queryList = parsedData.queries;
    } else {
      setValidationError(
        'Invalid batch format. JSON must contain a "queries" array, e.g. { "queries": [ ... ] }'
      );
      return;
    }

    // 3. Length validation
    if (queryList.length === 0) {
      setValidationError('Batch query list is empty. Please provide at least 1 query.');
      return;
    }
    if (queryList.length > 1000) {
      setValidationError(`Batch query list contains ${queryList.length} items, which exceeds the maximum limit of 1000.`);
      return;
    }

    // 4. Validate query item fields
    for (let i = 0; i < queryList.length; i++) {
      const q = queryList[i];
      if (!q || typeof q !== 'object') {
        setValidationError(`Query at index ${i + 1} is not a valid object.`);
        return;
      }
      if (!q.timestamp || typeof q.timestamp !== 'string' || !q.timestamp.trim()) {
        setValidationError(`Query #${i + 1} is missing required "timestamp" string.`);
        return;
      }
      if (!q.src_ip || typeof q.src_ip !== 'string' || !q.src_ip.trim()) {
        setValidationError(`Query #${i + 1} is missing required "src_ip" string.`);
        return;
      }
      if (!q.dst_ip || typeof q.dst_ip !== 'string' || !q.dst_ip.trim()) {
        setValidationError(`Query #${i + 1} is missing required "dst_ip" string.`);
        return;
      }
      if (!q.requested_server_name || typeof q.requested_server_name !== 'string' || !q.requested_server_name.trim()) {
        setValidationError(`Query #${i + 1} is missing required "requested_server_name" string.`);
        return;
      }
    }

    setLoading(true);
    try {
      const response = await analyzeBatchQueries(queryList, apiBaseUrl);
      setResult(response);
    } catch (err) {
      setApiError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card-panel" style={{ marginTop: '2rem' }}>
      <div className="section-heading">
        <h2>Batch Query Analysis</h2>
        <span className="section-tag live">POST /analyze</span>
      </div>

      <p className="panel-description">
        Analyze a collection of DNS queries independently. The sample includes an encoded-looking domain, but the model decides its label using its score and threshold. Sends <code>{`{ "queries": [...] }`}</code> to the backend and displays returned counts and itemized results.
      </p>

      {/* Preset helpers */}
      <div className="preset-bar">
        <span className="preset-label">Batch Actions:</span>
        <button
          type="button"
          className="btn btn-sm btn-outline"
          onClick={handleLoadSample}
          disabled={loading}
        >
          Load Sample Batch (4 queries)
        </button>
        <button
          type="button"
          className="btn btn-sm btn-outline"
          onClick={handleFormatJson}
          disabled={loading}
        >
          Format JSON
        </button>
        <button
          type="button"
          className="btn btn-sm btn-subtle"
          onClick={handleClear}
          disabled={loading}
        >
          Clear
        </button>
      </div>

      <form onSubmit={handleSubmit} className="batch-form">
        <div className="form-group">
          <label htmlFor="batch-json-editor" className="form-label">
            Batch JSON Payload (<code>{`{ "queries": [ ... ] }`}</code>) <span className="required">*</span>
          </label>
          <textarea
            id="batch-json-editor"
            className="form-textarea font-mono"
            rows="10"
            value={jsonInput}
            onChange={(e) => {
              setJsonInput(e.target.value);
              setValidationError('');
              setApiError('');
            }}
            placeholder='{\n  "queries": [\n    {\n      "timestamp": "2026-10-12T00:00:00Z",\n      "src_ip": "192.168.1.10",\n      "dst_ip": "8.8.8.8",\n      "requested_server_name": "example.com",\n      "query_type": "A"\n    }\n  ]\n}'
            disabled={loading}
          />
        </div>

        {/* Validation Error Message */}
        {validationError && (
          <div className="alert-box warning">
            <span className="alert-icon">⚠️</span>
            <div className="alert-content">
              <strong>Validation Error:</strong> {validationError}
            </div>
          </div>
        )}

        {/* API Error Message */}
        {apiError && (
          <div className="alert-box error">
            <span className="alert-icon">❌</span>
            <div className="alert-content">
              <strong>API Error:</strong> {apiError}
            </div>
          </div>
        )}

        <div className="form-actions">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                Analyzing Batch Queries...
              </>
            ) : (
              'Analyze Batch (/analyze)'
            )}
          </button>
        </div>
      </form>

      {/* Batch Results Display */}
      {result && (
        <div className="result-container">
          <div className="result-header">
            <h3>Batch Analysis Results</h3>
            <span className="section-tag live">
              Evaluated {result.total_queries} {result.total_queries === 1 ? 'Query' : 'Queries'}
            </span>
          </div>

          {/* Returned Counts Grid */}
          <div className="batch-counts-grid">
            <div className="batch-count-card total">
              <span className="batch-count-label">Total Queries</span>
              <span className="batch-count-val font-mono">{result.total_queries}</span>
              <span className="batch-count-sub">Processed in batch</span>
            </div>

            <div className="batch-count-card suspicious">
              <span className="batch-count-label">Suspicious Queries</span>
              <span className="batch-count-val font-mono text-danger">
                {result.suspicious_queries}
              </span>
              <span className="batch-count-sub">
                {result.total_queries > 0
                  ? `${((result.suspicious_queries / result.total_queries) * 100).toFixed(1)}% of batch`
                  : '0%'}
              </span>
            </div>

            <div className="batch-count-card benign">
              <span className="batch-count-label">Benign Queries</span>
              <span className="batch-count-val font-mono text-success">
                {result.benign_queries}
              </span>
              <span className="batch-count-sub">
                {result.total_queries > 0
                  ? `${((result.benign_queries / result.total_queries) * 100).toFixed(1)}% of batch`
                  : '0%'}
              </span>
            </div>
          </div>

          {/* Returned Results Table */}
          <div className="table-container" style={{ marginTop: '1.25rem' }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: '40px' }}>#</th>
                  <th>Requested Server Name</th>
                  <th>Prediction</th>
                  <th>Label</th>
                  <th>Attack score</th>
                  <th>Threshold</th>
                </tr>
              </thead>
              <tbody>
                {result.results && result.results.length > 0 ? (
                  result.results.map((item, idx) => (
                    <tr
                      key={idx}
                      className={item.prediction === 'suspicious' ? 'row-suspicious' : 'row-benign'}
                    >
                      <td className="font-mono text-muted">{idx + 1}</td>
                      <td>
                        <code className="font-mono">{item.requested_server_name}</code>
                      </td>
                      <td>
                        <span
                          className={`result-badge-inline ${
                            item.prediction === 'suspicious' ? 'suspicious' : 'benign'
                          }`}
                        >
                          {item.prediction === 'suspicious' ? '🚨 suspicious' : '✅ benign'}
                        </span>
                      </td>
                      <td className="font-mono">{item.label}</td>
                      <td>
                        <span
                          className={`font-mono ${
                            item.prediction === 'suspicious' ? 'text-danger' : 'text-success'
                          }`}
                          style={{ fontWeight: 600 }}
                        >
                          {(item.attack_probability * 100).toFixed(2)}%
                        </span>
                        <span className="text-muted" style={{ fontSize: '0.75rem', marginLeft: '0.4rem' }}>
                          ({item.attack_probability.toFixed(4)})
                        </span>
                      </td>
                      <td className="font-mono text-cyan">
                        {item.decision_threshold.toFixed(4)}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '2rem' }}>
                      No results returned in batch.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
