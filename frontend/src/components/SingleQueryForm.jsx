import React, { useState } from 'react';
import { predictSingleQuery } from '../api/client';

export default function SingleQueryForm({ apiBaseUrl, onPredictionCompleted }) {
  const [formData, setFormData] = useState({
    timestamp: '',
    src_ip: '',
    dst_ip: '',
    requested_server_name: '',
    query_type: 'A',
  });

  const [loading, setLoading] = useState(false);
  const [validationError, setValidationError] = useState('');
  const [apiError, setApiError] = useState('');
  const [result, setResult] = useState(null);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    setValidationError('');
    setApiError('');
  };

  const handleSetCurrentTimestamp = () => {
    setFormData((prev) => ({
      ...prev,
      timestamp: new Date().toISOString(),
    }));
    setValidationError('');
  };

  const loadBenignSample = () => {
    setFormData({
      timestamp: new Date().toISOString(),
      src_ip: '192.168.1.105',
      dst_ip: '8.8.8.8',
      requested_server_name: 'api.github.com',
      query_type: 'A',
    });
    setValidationError('');
    setApiError('');
    setResult(null);
  };

  const loadEncodedDomainSample = () => {
    setFormData({
      timestamp: new Date().toISOString(),
      src_ip: '10.0.30.186',
      dst_ip: '10.0.0.2',
      requested_server_name: 's.2ukez6wzvq7lttlpwff5rkg3.data-relay.info',
      query_type: 'A',
    });
    setValidationError('');
    setApiError('');
    setResult(null);
  };

  const handleClear = () => {
    setFormData({
      timestamp: '',
      src_ip: '',
      dst_ip: '',
      requested_server_name: '',
      query_type: 'A',
    });
    setValidationError('');
    setApiError('');
    setResult(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setValidationError('');
    setApiError('');
    setResult(null);

    // Client-side validation for required fields
    if (!formData.timestamp.trim()) {
      setValidationError('Timestamp is required. Click "Current Time" or enter an ISO timestamp (e.g. 2026-10-12T00:00:00Z).');
      return;
    }
    if (!formData.src_ip.trim()) {
      setValidationError('Source IP (src_ip) is required.');
      return;
    }
    if (!formData.dst_ip.trim()) {
      setValidationError('Destination IP (dst_ip) is required.');
      return;
    }
    if (!formData.requested_server_name.trim()) {
      setValidationError('Requested Server Name (requested_server_name) is required.');
      return;
    }

    setLoading(true);
    try {
      const response = await predictSingleQuery(formData, apiBaseUrl);
      setResult(response);
      if (onPredictionCompleted) {
        onPredictionCompleted();
      }
    } catch (err) {
      setApiError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card-panel">
      <div className="section-heading">
        <h2>Single Query Inference</h2>
        <span className="section-tag live">POST /predict</span>
      </div>

      <p className="panel-description">
        Submit an individual DNS query to evaluate whether it exhibits exfiltration behavior.
      </p>

      {/* Preset helpers */}
      <div className="preset-bar">
        <span className="preset-label">Quick Presets:</span>
        <button
          type="button"
          className="btn btn-sm btn-outline"
          onClick={loadBenignSample}
          disabled={loading}
        >
          Benign Sample
        </button>
        <button
          type="button"
          className="btn btn-sm btn-outline"
          onClick={loadEncodedDomainSample}
          disabled={loading}
        >
          Encoded-Domain Example
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

      <form onSubmit={handleSubmit} className="query-form">
        <div className="form-grid">
          {/* Timestamp */}
          <div className="form-group">
            <div className="form-label-row">
              <label htmlFor="single-timestamp" className="form-label">
                Timestamp <span className="required">*</span>
              </label>
              <button
                type="button"
                className="btn-link"
                onClick={handleSetCurrentTimestamp}
                tabIndex="-1"
              >
                Current Time
              </button>
            </div>
            <input
              id="single-timestamp"
              type="text"
              name="timestamp"
              className="form-input"
              value={formData.timestamp}
              onChange={handleInputChange}
              placeholder="e.g. 2026-10-12T00:00:00Z"
              disabled={loading}
            />
          </div>

          {/* Query Type (optional) */}
          <div className="form-group">
            <label htmlFor="single-query-type" className="form-label">
              Query Type <span className="optional">(optional, default: A)</span>
            </label>
            <select
              id="single-query-type"
              name="query_type"
              className="form-select"
              value={formData.query_type}
              onChange={handleInputChange}
              disabled={loading}
            >
              <option value="A">A (IPv4)</option>
              <option value="AAAA">AAAA (IPv6)</option>
              <option value="TXT">TXT (Text record)</option>
              <option value="MX">MX (Mail)</option>
              <option value="CNAME">CNAME (Alias)</option>
              <option value="NS">NS (Name Server)</option>
              <option value="PTR">PTR (Pointer)</option>
              <option value="SRV">SRV (Service)</option>
            </select>
          </div>

          {/* Source IP */}
          <div className="form-group">
            <label htmlFor="single-src-ip" className="form-label">
              Source IP (src_ip) <span className="required">*</span>
            </label>
            <input
              id="single-src-ip"
              type="text"
              name="src_ip"
              className="form-input"
              value={formData.src_ip}
              onChange={handleInputChange}
              placeholder="e.g. 192.168.1.100"
              disabled={loading}
            />
          </div>

          {/* Destination IP */}
          <div className="form-group">
            <label htmlFor="single-dst-ip" className="form-label">
              Destination IP (dst_ip) <span className="required">*</span>
            </label>
            <input
              id="single-dst-ip"
              type="text"
              name="dst_ip"
              className="form-input"
              value={formData.dst_ip}
              onChange={handleInputChange}
              placeholder="e.g. 8.8.8.8"
              disabled={loading}
            />
          </div>

          {/* Requested Server Name */}
          <div className="form-group form-col-full">
            <label htmlFor="single-server-name" className="form-label">
              Requested Server Name (Domain) <span className="required">*</span>
            </label>
            <input
              id="single-server-name"
              type="text"
              name="requested_server_name"
              className="form-input font-mono"
              value={formData.requested_server_name}
              onChange={handleInputChange}
              placeholder="e.g. example.com or payload.exfiltration.attacker.com"
              disabled={loading}
            />
          </div>
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
                Evaluating Query...
              </>
            ) : (
              'Run Prediction (/predict)'
            )}
          </button>
        </div>
      </form>

      {/* Prediction Result Display */}
      {result && (
        <div className="result-container">
          <div className="result-header">
            <h3>Prediction Result</h3>
            <span
              className={`result-badge ${
                result.prediction === 'suspicious' ? 'suspicious' : 'benign'
              }`}
            >
              {result.prediction === 'suspicious' ? '🚨 SUSPICIOUS' : '✅ BENIGN'}
            </span>
          </div>

          <div className="result-metrics-grid">
            <div className="result-card">
              <span className="result-card-label">Prediction</span>
              <span
                className={`result-card-value font-mono ${
                  result.prediction === 'suspicious' ? 'text-danger' : 'text-success'
                }`}
              >
                {result.prediction}
              </span>
              <span className="result-card-sub">Label: {result.label}</span>
            </div>

            <div className="result-card">
              <span className="result-card-label">Attack score</span>
              <span
                className={`result-card-value font-mono ${
                  result.prediction === 'suspicious' ? 'text-danger' : 'text-success'
                }`}
              >
                {(result.attack_probability * 100).toFixed(2)}%
              </span>
              <span className="result-card-sub font-mono">
                Raw: {result.attack_probability.toFixed(4)}
              </span>
            </div>

            <div className="result-card">
              <span className="result-card-label">Decision Threshold</span>
              <span className="result-card-value font-mono text-cyan">
                {result.decision_threshold.toFixed(4)}
              </span>
              <span className="result-card-sub">
                {result.attack_probability >= result.decision_threshold
                  ? 'Score ≥ Threshold (Flagged)'
                  : 'Score < Threshold (Clear)'}
              </span>
            </div>
          </div>

          <div className="result-meta-footer">
            <span className="meta-label">Evaluated Domain:</span>
            <code className="meta-domain">{formData.requested_server_name}</code>
          </div>
        </div>
      )}
    </div>
  );
}
