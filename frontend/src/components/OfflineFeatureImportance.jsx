import React from 'react';
import { OFFLINE_EVALUATION } from '../data/offlineEvaluationData';

export default function OfflineFeatureImportance() {
  const { featureImportance, featureImportanceNote } = OFFLINE_EVALUATION;

  return (
    <div className="card-panel">
      <div className="section-heading">
        <h2>Offline Feature Importance</h2>
        <span className="section-tag offline">10 Input Features</span>
      </div>

      <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '1.25rem' }}>
        Relative contribution of extracted DNS attributes toward detecting simulated exfiltration queries:
      </div>

      <div className="feature-list">
        {featureImportance.map((item) => (
          <div key={item.feature} className="feature-item">
            <div className="feature-meta">
              <span className="feature-name">
                <span style={{ color: '#64748b', marginRight: '0.5rem' }}>#{item.rank}</span>
                {item.feature}
              </span>
              <span className="feature-val">{item.percent.toFixed(2)}%</span>
            </div>
            <div className="progress-track" title={`${item.feature}: ${item.percent}%`}>
              <div 
                className="progress-fill" 
                style={{ width: `${item.percent}%` }}
              ></div>
            </div>
            <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
              {item.description}
            </div>
          </div>
        ))}
      </div>

      <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '1.25rem', borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '0.75rem' }}>
        ℹ️ <em>{featureImportanceNote}</em>
      </div>
    </div>
  );
}
