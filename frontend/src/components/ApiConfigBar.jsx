import React, { useState } from 'react';
import { checkApiHealth } from '../api/client';

export default function ApiConfigBar({
  apiBaseUrl,
  setApiBaseUrl,
  healthStatus,
  setHealthStatus,
}) {
  const [testing, setTesting] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');

  const handleTestHealth = async () => {
    setTesting(true);
    setStatusMessage('');
    try {
      const data = await checkApiHealth(apiBaseUrl);
      if (data.status === 'healthy' && data.model_loaded) {
        setHealthStatus('online');
        setStatusMessage('Backend API is healthy and Random Forest model bundle is loaded.');
      } else {
        setHealthStatus('warning');
        setStatusMessage(`Backend responded: status=${data.status}, model_loaded=${data.model_loaded}`);
      }
    } catch (err) {
      setHealthStatus('offline');
      setStatusMessage(err.message);
    } finally {
      setTesting(false);
    }
  };

  const handleResetToProxy = () => {
    setApiBaseUrl('');
    setHealthStatus('unknown');
    setStatusMessage('');
  };

  return (
    <div className="api-config-bar">
      <div className="api-config-left">
        <span className="api-config-label">API Endpoint:</span>
        <input
          type="text"
          className="api-input"
          value={apiBaseUrl}
          onChange={(e) => {
            setApiBaseUrl(e.target.value);
            setHealthStatus('unknown');
            setStatusMessage('');
          }}
          placeholder="Proxy: / (Vite proxy -> 127.0.0.1:8000)"
          title="Leave blank to use the Vite dev proxy (recommended)"
        />
        {apiBaseUrl && (
          <button
            type="button"
            className="btn btn-sm btn-subtle"
            onClick={handleResetToProxy}
            title="Reset to local Vite dev proxy"
          >
            Reset to Proxy
          </button>
        )}
        <button
          type="button"
          className="btn btn-sm btn-outline"
          onClick={handleTestHealth}
          disabled={testing}
        >
          {testing ? 'Testing...' : 'Test /health'}
        </button>
        {!apiBaseUrl && (
          <span className="proxy-indicator" title="Requests are proxied by Vite to http://127.0.0.1:8000 without CORS restrictions">
            ⚡ Vite Proxy Active
          </span>
        )}
      </div>

      <div className="api-config-right">
        {healthStatus === 'online' && (
          <span className="status-badge success">
            <span className="status-dot"></span> Backend Online (Model Loaded)
          </span>
        )}
        {healthStatus === 'warning' && (
          <span className="status-badge warning">
            <span className="status-dot"></span> Backend Warning
          </span>
        )}
        {healthStatus === 'offline' && (
          <span className="status-badge danger">
            <span className="status-dot"></span> Backend Offline / Unreachable
          </span>
        )}
        {healthStatus === 'unknown' && (
          <span className="status-badge neutral">
            <span className="status-dot"></span> Not Tested
          </span>
        )}
      </div>

      {statusMessage && (
        <div className={`api-status-detail ${healthStatus}`}>
          {healthStatus === 'offline' ? '⚠️ ' : 'ℹ️ '}
          {statusMessage}
        </div>
      )}
    </div>
  );
}
