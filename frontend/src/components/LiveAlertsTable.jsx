import React from 'react';

export default function LiveAlertsTable() {
  return (
    <div className="card-panel" style={{ marginBottom: '2rem' }}>
      <div className="section-heading">
        <h2>Suspicious DNS Activity (Alert Feed)</h2>
        <span className="section-tag live">Real-Time Alerts</span>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Queried Domain / Subdomain</th>
              <th>Client IP</th>
              <th>Risk Level</th>
              <th>Model Probability</th>
              <th>Trigger Indicators</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td colSpan="6" style={{ textAlign: 'center', padding: '3.5rem 1.5rem' }}>
                <div style={{ fontSize: '1.75rem', marginBottom: '0.5rem', opacity: 0.5 }}>🚨</div>
                <div style={{ fontWeight: 600, color: '#94a3b8', marginBottom: '0.25rem' }}>
                  No alerts yet — waiting for incoming DNS query stream
                </div>
                <div style={{ fontSize: '0.8rem', color: '#64748b', maxWidth: '480px', margin: '0 auto' }}>
                  When suspicious exfiltration traffic is detected by the inference pipeline,
                  flagged queries, calculated risk levels, and contributing indicators will appear here.
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
