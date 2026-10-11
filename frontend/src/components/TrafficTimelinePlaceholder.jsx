import React from 'react';

export default function TrafficTimelinePlaceholder() {
  return (
    <div className="card-panel">
      <div className="section-heading">
        <h2>Traffic Analysis Timeline</h2>
        <span className="section-tag live">Live Chart Placeholder</span>
      </div>

      <div className="empty-state-box">
        <div className="empty-icon">📈</div>
        <div className="empty-title">No traffic timeline available yet</div>
        <p className="empty-desc">
          Live network packet sniffing (Scapy) and dataset replay are not currently active.
          Once live packet capture or dataset replay is connected, this chart will render query volume over time.
        </p>
      </div>
    </div>
  );
}
