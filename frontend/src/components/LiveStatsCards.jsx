import React from 'react';

export default function LiveStatsCards() {
  return (
    <section>
      <div className="section-heading">
        <h2>Live Traffic Overview</h2>
        <span className="section-tag live">Operational Stream (Empty State)</span>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-header">
            <span>Total DNS Queries</span>
            <span>📡</span>
          </div>
          <div className="stat-card-value blank">--</div>
          <div className="stat-card-subtext">Live packet data is not available yet (capture stream pending)</div>
        </div>

        <div className="stat-card">
          <div className="stat-card-header">
            <span>Suspicious Queries</span>
            <span>⚠️</span>
          </div>
          <div className="stat-card-value blank">--</div>
          <div className="stat-card-subtext">Awaiting live feed / model scoring</div>
        </div>

        <div className="stat-card">
          <div className="stat-card-header">
            <span>Benign Queries</span>
            <span>✅</span>
          </div>
          <div className="stat-card-value blank">--</div>
          <div className="stat-card-subtext">Awaiting live feed / model scoring</div>
        </div>
      </div>
    </section>
  );
}
