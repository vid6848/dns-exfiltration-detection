import React from 'react';

export default function Header() {
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
        <div className="status-pill offline" title="FastAPI server is not connected yet">
          <span className="status-dot"></span>
          <span>Backend API: Disconnected (Pending)</span>
        </div>
        <div className="status-pill verified" title="Loaded from verified offline experiment files">
          <span className="status-dot"></span>
          <span>Offline Results: Verified</span>
        </div>
      </div>
    </header>
  );
}
