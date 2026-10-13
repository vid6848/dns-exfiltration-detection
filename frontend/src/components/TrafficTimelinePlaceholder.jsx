import React from 'react';

export default function TrafficTimelinePlaceholder({ stats }) {
  const total = stats ? stats.total_processed : 0;
  const suspicious = stats ? stats.total_suspicious : 0;
  const benign = stats ? stats.total_benign : 0;

  return (
    <div className="card-panel">
      <div className="section-heading">
        <h2>Traffic Analysis Stream</h2>
        <span className="section-tag live">GET /statistics</span>
      </div>

      {total > 0 ? (
        <div style={{ padding: '1rem 0' }}>
          <div style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem' }}>
            <span>Traffic Breakdown ({total.toLocaleString()} total queries)</span>
            <span className="font-mono text-cyan">
              {((benign / total) * 100).toFixed(1)}% Benign / {((suspicious / total) * 100).toFixed(1)}% Suspicious
            </span>
          </div>

          {/* Visual distribution bar */}
          <div style={{
            height: '14px',
            width: '100%',
            backgroundColor: 'rgba(244, 63, 94, 0.4)',
            borderRadius: '7px',
            overflow: 'hidden',
            display: 'flex',
            marginBottom: '1.25rem',
          }}>
            <div style={{
              width: `${(benign / total) * 100}%`,
              backgroundColor: '#10b981',
              height: '100%',
              transition: 'width 0.4s ease',
            }} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
            <div style={{ background: 'rgba(16, 185, 129, 0.1)', padding: '0.6rem 0.85rem', borderRadius: '6px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
              <div style={{ color: '#6ee7b7', fontWeight: 600 }}>Clean Queries</div>
              <div className="font-mono" style={{ fontSize: '1.25rem', color: '#ffffff', marginTop: '0.2rem' }}>{benign.toLocaleString()}</div>
            </div>
            <div style={{ background: 'rgba(244, 63, 94, 0.1)', padding: '0.6rem 0.85rem', borderRadius: '6px', border: '1px solid rgba(244, 63, 94, 0.2)' }}>
              <div style={{ color: '#fda4af', fontWeight: 600 }}>Flagged Attacks</div>
              <div className="font-mono" style={{ fontSize: '1.25rem', color: '#ffffff', marginTop: '0.2rem' }}>{suspicious.toLocaleString()}</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="empty-state-box">
          <div className="empty-icon">📈</div>
          <div className="empty-title">Awaiting Query Traffic</div>
          <p className="empty-desc">
            No DNS events have been submitted to the inference pipeline yet. Run a single query prediction or batch analysis above to populate real traffic metrics.
          </p>
        </div>
      )}
    </div>
  );
}
