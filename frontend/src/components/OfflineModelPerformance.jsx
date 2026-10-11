import React from 'react';
import { OFFLINE_EVALUATION } from '../data/offlineEvaluationData';

export default function OfflineModelPerformance() {
  const { randomForest, statisticalBaseline, meta } = OFFLINE_EVALUATION;

  return (
    <div className="card-panel">
      <div className="section-heading">
        <h2>Offline Model Evaluation Results</h2>
        <span className="section-tag offline">Verified Experiment</span>
      </div>

      {/* Note explicitly placed beside/above the offline results as requested */}
      <div className="scope-callout">
        <span>ℹ️</span>
        <div>
          <strong>Evaluation Note: </strong>
          <span>{meta.scopeNote}</span>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Source: <code>{meta.verifiedSourceFile}</code> (Dataset: {meta.dataset}, N = {meta.datasetRecords.toLocaleString()})
          </div>
        </div>
      </div>

      <div className="metrics-comparison">
        {/* Champion Model: Random Forest */}
        <div className="model-box champion">
          <div className="model-box-header">
            <div>
              <div className="model-box-title">Random Forest (Final Model)</div>
              <div style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>
                Selected Candidate (Threshold: {meta.decisionThreshold})
              </div>
            </div>
            <span style={{ fontSize: '1.25rem' }}>🌲</span>
          </div>

          <div className="metric-row">
            <span className="metric-label">Precision</span>
            <span className="metric-value highlight">{randomForest.precision.toFixed(1)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Recall</span>
            <span className="metric-value">{randomForest.recall.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">F1-Score</span>
            <span className="metric-value highlight">{randomForest.f1Score.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Accuracy</span>
            <span className="metric-value">{randomForest.accuracy.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">False Positive Rate</span>
            <span className="metric-value highlight">{randomForest.falsePositiveRate.toFixed(2)}% (0 / 43,340)</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">True Positives</span>
            <span className="metric-value">{randomForest.truePositives.toLocaleString()} / {randomForest.totalAttacks.toLocaleString()}</span>
          </div>
        </div>

        {/* Comparison: Statistical Baseline */}
        <div className="model-box">
          <div className="model-box-header">
            <div>
              <div className="model-box-title">Statistical Baseline</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Heuristic Multi-Threshold Rule
              </div>
            </div>
            <span style={{ fontSize: '1.25rem' }}>📏</span>
          </div>

          <div className="metric-row">
            <span className="metric-label">Precision</span>
            <span className="metric-value">{statisticalBaseline.precision.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Recall</span>
            <span className="metric-value">{statisticalBaseline.recall.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">F1-Score</span>
            <span className="metric-value">{statisticalBaseline.f1Score.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Accuracy</span>
            <span className="metric-value">{statisticalBaseline.accuracy.toFixed(2)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">False Positive Rate</span>
            <span className="metric-value" style={{ color: '#f59e0b' }}>
              {statisticalBaseline.falsePositiveRate.toFixed(2)}% ({statisticalBaseline.falsePositives} / 43,340)
            </span>
          </div>
          <div className="metric-row">
            <span className="metric-label">True Positives</span>
            <span className="metric-value">{statisticalBaseline.truePositives.toLocaleString()} / {statisticalBaseline.totalAttacks.toLocaleString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
