import React from 'react';

export default function Header({ healthStatus = 'offline' }) {
  const getBackendStatusPill = () => {
    if (healthStatus === 'online') {
      return (
        <div className="status-pill verified" title="Connected to FastAPI backend with model loaded">
          <span className="status-dot"></span>
          <span>Backend API: Online (Healthy)</span>
        </div>
      );
    }
    if (healthStatus === 'warning') {
      return (
        <div className="status-pill offline" title="Backend responded with a warning">
          <span className="status-dot"></span>
          <span>Backend API: Warning</span>
        </div>
      );
    }
    return (
      <div className="status-pill offline" title="FastAPI server is not yet connected">
        <span className="status-dot"></span>
        <span>Backend API: Disconnected (Pending)</span>
      </div>
    );
  };

  return (
    <header className="dashboard-header">
      <div className="header-title-group">
        <h1>
          <span>🛡️</span>
          <span>DNS Exfiltration Detection Dashboard</span>
        </h1>
        <p>CyberTrace | Cryptography & Network Security (CE305/CS305)</p>
      </div>

      <div className="badge-row">
        {getBackendStatusPill()}
        <div className="status-pill verified" title="Loaded from verified offline experiment files">
          <span className="status-dot"></span>
          <span>Offline Results: Verified</span>
        </div>
      </div>
    </header>
  );
}
