import React from 'react';
import Header from './components/Header';
import LiveStatsCards from './components/LiveStatsCards';
import TrafficTimelinePlaceholder from './components/TrafficTimelinePlaceholder';
import LiveAlertsTable from './components/LiveAlertsTable';
import OfflineModelPerformance from './components/OfflineModelPerformance';
import OfflineFeatureImportance from './components/OfflineFeatureImportance';

export default function App() {
  return (
    <div className="dashboard-container">
      <Header />

      <div className="notice-banner">
        <span style={{ fontSize: '1.25rem' }}>⚠️</span>
        <div>
          <strong>Operational Notice: </strong>
          The backend API (FastAPI) is not yet running. Live network metrics and real-time alerts below 
          display intentional blank values and empty states. Offline model performance metrics 
          are loaded strictly from verified repository experiment artifacts.
        </div>
      </div>

      {/* 1. Live Operational Stream (Empty States) */}
      <LiveStatsCards />

      {/* 2. Traffic Analysis & Alerts Table */}
      <LiveAlertsTable />

      {/* 3. Two-Column Layout for Timeline & Offline Evaluation */}
      <div className="dashboard-columns">
        <TrafficTimelinePlaceholder />
        <OfflineFeatureImportance />
      </div>

      {/* 4. Offline Model Performance Comparison */}
      <OfflineModelPerformance />
    </div>
  );
}
