import React from 'react';

export default function LiveAlertsTable({ alerts, loading, onRefresh }) {
  const alertList = alerts || [];

  return (
    <div className="card-panel" style={{ marginBottom: '2rem' }}>
      <div className="section-heading">
        <div>
          <h2>Suspicious DNS Activity (Alert Feed)</h2>
          <span className="section-tag live">GET /alerts</span>
        </div>
        {onRefresh && (
          <button
            type="button"
            className="btn btn-sm btn-outline"
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? 'Refreshing...' : '🔄 Refresh Feed'}
          </button>
        )}
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Queried Domain / Subdomain</th>
              <th>Client IP</th>
              <th>Risk Level</th>
              <th>Attack Score</th>
              <th>Indicators</th>
            </tr>
          </thead>
          <tbody>
            {alertList.length > 0 ? (
              alertList.map((alert, idx) => (
                <tr key={alert.alert_id || idx} className="row-suspicious">
                  <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                    {alert.timestamp}
                  </td>
                  <td>
                    <code className="font-mono text-danger">
                      {alert.requested_server_name}
                    </code>
                  </td>
                  <td className="font-mono">{alert.src_ip}</td>
                  <td>
                    <span className="result-badge-inline suspicious">
                      {alert.risk_label || 'CRITICAL'}
                    </span>
                  </td>
                  <td>
                    <span className="font-mono text-danger" style={{ fontWeight: 600 }}>
                      {((alert.attack_score ?? 0) * 100).toFixed(2)}%
                    </span>
                    <span className="text-muted" style={{ fontSize: '0.725rem', marginLeft: '0.35rem' }}>
                      (τ = {alert.decision_threshold?.toFixed(2) || '0.90'})
                    </span>
                  </td>
                  <td style={{ fontSize: '0.75rem' }}>
                    {alert.rule_indicators ? (
                      <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                        {alert.rule_indicators.entropy_flag && (
                          <span className="proxy-indicator" style={{ borderColor: 'rgba(244,63,94,0.4)', color: '#fb7185' }}>
                            Entropy ≥ 4.31
                          </span>
                        )}
                        {alert.rule_indicators.query_length_flag && (
                          <span className="proxy-indicator" style={{ borderColor: 'rgba(244,63,94,0.4)', color: '#fb7185' }}>
                            Length ≥ 52
                          </span>
                        )}
                        {alert.rule_indicators.query_frequency_flag && (
                          <span className="proxy-indicator" style={{ borderColor: 'rgba(244,63,94,0.4)', color: '#fb7185' }}>
                            Frequency ≥ 41
                          </span>
                        )}
                        {alert.rule_indicators.unique_subdomains_flag && (
                          <span className="proxy-indicator" style={{ borderColor: 'rgba(244,63,94,0.4)', color: '#fb7185' }}>
                            Subdomains ≥ 41
                          </span>
                        )}
                        {alert.rule_indicators.baseline_flagged && (
                          <span className="proxy-indicator" style={{ borderColor: 'rgba(245,158,11,0.6)', color: '#f59e0b', fontWeight: 700 }}>
                            Baseline Corroborated (≥2)
                          </span>
                        )}
                      </div>
                    ) : (
                      '--'
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '3.5rem 1.5rem' }}>
                  <div style={{ fontSize: '1.75rem', marginBottom: '0.5rem', opacity: 0.5 }}>🚨</div>
                  <div style={{ fontWeight: 600, color: '#94a3b8', marginBottom: '0.25rem' }}>
                    No alerts in current buffer — waiting for incoming queries
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#64748b', maxWidth: '480px', margin: '0 auto' }}>
                    When queries cross the selected 0.90 decision threshold via single query prediction, JSON batch analysis, or CSV upload, they appear dynamically here.
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
