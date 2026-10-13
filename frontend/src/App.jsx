import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import ApiConfigBar from './components/ApiConfigBar';
import SingleQueryForm from './components/SingleQueryForm';
import BatchAnalysisForm from './components/BatchAnalysisForm';
import LiveStatsCards from './components/LiveStatsCards';
import TrafficTimelinePlaceholder from './components/TrafficTimelinePlaceholder';
import LiveAlertsTable from './components/LiveAlertsTable';
import OfflineModelPerformance from './components/OfflineModelPerformance';
import OfflineFeatureImportance from './components/OfflineFeatureImportance';
import {
  DEFAULT_API_BASE_URL,
  checkApiHealth,
  fetchLiveAlerts,
  fetchLiveStatistics,
} from './api/client';

export default function App() {
  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_API_BASE_URL);
  const [healthStatus, setHealthStatus] = useState('unknown');
  const [stats, setStats] = useState({
    total_processed: 0,
    total_suspicious: 0,
    total_benign: 0,
    suspicious_rate: 0.0,
    has_live_data: false,
  });
  const [alerts, setAlerts] = useState([]);
  const [loadingFeeds, setLoadingFeeds] = useState(false);

  const refreshTelemetry = useCallback(() => {
    setLoadingFeeds(true);
    Promise.all([
      fetchLiveStatistics(apiBaseUrl).catch(() => null),
      fetchLiveAlerts(50, apiBaseUrl).catch(() => null),
    ])
      .then(([statsData, alertsData]) => {
        if (statsData) {
          setStats(statsData);
        }
        if (alertsData && alertsData.alerts) {
          setAlerts(alertsData.alerts);
        }
      })
      .finally(() => {
        setLoadingFeeds(false);
      });
  }, [apiBaseUrl]);

  // Check health and initial telemetry on mount or baseUrl change
  useEffect(() => {
    let isMounted = true;
    checkApiHealth(apiBaseUrl)
      .then((data) => {
        if (isMounted) {
          if (data.status === 'healthy' && data.model_loaded) {
            setHealthStatus('online');
            refreshTelemetry();
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
  }, [apiBaseUrl, refreshTelemetry]);

  return (
    <div className="dashboard-container">
      <Header healthStatus={healthStatus} />

      <div className="notice-banner">
        <span style={{ fontSize: '1.25rem' }}>ℹ️</span>
        <div>
          <strong>CyberTrace Integrated Detection Platform: </strong>
          Active REST API serving single-query inference (<code>/predict</code>), JSON batch analysis (<code>/analyze</code>),
          and multipart CSV ingestion (<code>/analyze/csv</code>). Live telemetry and alert feeds below update automatically from <code>/statistics</code> and <code>/alerts</code>.
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
        <SingleQueryForm apiBaseUrl={apiBaseUrl} onPredictionCompleted={refreshTelemetry} />
        <BatchAnalysisForm apiBaseUrl={apiBaseUrl} onAnalysisCompleted={refreshTelemetry} />
      </section>

      {/* Continuous Live Operational Stream */}
      <LiveStatsCards stats={stats} loading={loadingFeeds} />

      {/* Suspicious DNS Activity Alert Feed */}
      <LiveAlertsTable alerts={alerts} loading={loadingFeeds} onRefresh={refreshTelemetry} />

      {/* Traffic Breakdown & Feature Importance */}
      <div className="dashboard-columns">
        <TrafficTimelinePlaceholder stats={stats} />
        <OfflineFeatureImportance />
      </div>

      {/* Dynamic Model Performance Benchmarks */}
      <OfflineModelPerformance apiBaseUrl={apiBaseUrl} />
    </div>
  );
}
