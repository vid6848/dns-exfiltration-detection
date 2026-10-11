import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import ApiConfigBar from './components/ApiConfigBar';
import SingleQueryForm from './components/SingleQueryForm';
import BatchAnalysisForm from './components/BatchAnalysisForm';
import LiveStatsCards from './components/LiveStatsCards';
import TrafficTimelinePlaceholder from './components/TrafficTimelinePlaceholder';
import LiveAlertsTable from './components/LiveAlertsTable';
import OfflineModelPerformance from './components/OfflineModelPerformance';
import OfflineFeatureImportance from './components/OfflineFeatureImportance';
import { DEFAULT_API_BASE_URL, checkApiHealth } from './api/client';

export default function App() {
  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_API_BASE_URL);
  const [healthStatus, setHealthStatus] = useState('unknown');

  // Check the default API once when the dashboard loads. Custom endpoints can
  // be checked on demand from the Test /health button.
  useEffect(() => {
    let isMounted = true;
    checkApiHealth(DEFAULT_API_BASE_URL)
      .then((data) => {
        if (isMounted) {
          if (data.status === 'healthy' && data.model_loaded) {
            setHealthStatus('online');
          } else {
            setHealthStatus('warning');
          }
        }
      })
      .catch(() => {
        if (isMounted) {
          setHealthStatus('offline');
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <div className="dashboard-container">
      <Header healthStatus={healthStatus} />

      <div className="notice-banner">
        <span style={{ fontSize: '1.25rem' }}>ℹ️</span>
        <div>
          <strong>Interactive Detection API: </strong>
          Interactive single-query prediction (<code>/predict</code>) and batch query analysis (<code>/analyze</code>)
          are active below using Pranay&apos;s API contract (PR #4). Live packet-stream metrics and the alert feed below
          display intentional empty states until continuous packet capture is connected.
        </div>
      </div>

      {/* API Endpoint Configuration & Status Bar */}
      <ApiConfigBar
        apiBaseUrl={apiBaseUrl}
        setApiBaseUrl={setApiBaseUrl}
        healthStatus={healthStatus}
        setHealthStatus={setHealthStatus}
      />

      {/* Interactive Inference Section (Single Query & Batch Analysis) */}
      <section className="interactive-section" style={{ marginTop: '2rem', marginBottom: '2.5rem' }}>
        <SingleQueryForm apiBaseUrl={apiBaseUrl} />
        <BatchAnalysisForm apiBaseUrl={apiBaseUrl} />
      </section>

      {/* Continuous Live Operational Stream (Empty States) */}
      <LiveStatsCards />

      {/* Continuous Traffic Analysis & Alert Feed (Empty State) */}
      <LiveAlertsTable />

      {/* Offline Artifact Visualizations: Timeline & Feature Importance */}
      <div className="dashboard-columns">
        <TrafficTimelinePlaceholder />
        <OfflineFeatureImportance />
      </div>

      {/* Offline Model Performance Benchmarks */}
      <OfflineModelPerformance />
    </div>
  );
}
