import React from 'react';

export default function LiveStatsCards({ stats, loading }) {
  const hasLive = stats && stats.has_live_data;

  return (
    <section>
      <div className="section-heading">
        <h2>Live Traffic Overview</h2>
        <span className={`section-tag ${hasLive ? 'live' : 'offline'}`}>
          {hasLive ? 'Live API Telemetry' : 'Awaiting Ingestion Stream'}
        </span>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-header">
            <span>Total DNS Queries</span>
            <span>📡</span>
          </div>
          <div className="stat-card-value font-mono">
            {loading ? '...' : (hasLive ? stats.total_processed.toLocaleString() : '--')}
          </div>
          <div className="stat-card-subtext">
            {hasLive ? 'Cumulative processed DNS queries' : 'Awaiting query ingestion stream'}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card-header">
            <span>Suspicious Queries</span>
            <span>⚠️</span>
          </div>
          <div className="stat-card-value font-mono text-danger">
            {loading ? '...' : (hasLive ? stats.total_suspicious.toLocaleString() : '--')}
          </div>
          <div className="stat-card-subtext">
            {hasLive
              ? `${(stats.suspicious_rate * 100).toFixed(1)}% flagged by calibrated RF model`
              : 'Awaiting feed / model scoring'}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card-header">
            <span>Benign Queries</span>
            <span>✅</span>
          </div>
          <div className="stat-card-value font-mono text-success">
            {loading ? '...' : (hasLive ? stats.total_benign.toLocaleString() : '--')}
          </div>
          <div className="stat-card-subtext">
            {hasLive ? 'Verified clean DNS requests' : 'Awaiting feed / model scoring'}
          </div>
        </div>
      </div>
    </section>
  );
}
