/**
 * Offline Evaluation Data
 * 
 * SOURCED DIRECTLY FROM COMMITTED PROJECT EVALUATION ARTIFACTS:
 * - evaluation/results/baseline_vs_rf_v2/baseline_vs_rf_metrics.json
 * - evaluation/results/baseline_vs_rf_v2/feature_importance/feature_importance.json
 * 
 * DO NOT EDIT OR INVENT VALUES. All numbers reflect the verified offline diagnostic evaluation.
 */

export const OFFLINE_EVALUATION = {
  meta: {
    dataset: "cleaned_unified_v0.1.csv",
    datasetRecords: 45240,
    benignCount: 43340,
    attackCount: 1900,
    modelArtifact: "artifacts/fast_burst_v0.1/random_forest.joblib",
    decisionThreshold: 0.90,
    slidingWindowSeconds: 60.0,
    // Note explicitly requested to appear beside the results:
    scopeNote: "Previously inspected diagnostic development evaluation. Not an independent final test or proof of real-world generalization.",
    verifiedSourceFile: "evaluation/results/baseline_vs_rf_v2/baseline_vs_rf_metrics.json"
  },
  randomForest: {
    name: "Random Forest (Trained Model)",
    type: "Supervised Classifier",
    accuracy: 99.63,
    precision: 100.0,
    recall: 91.21,
    f1Score: 95.40,
    falsePositiveRate: 0.00,
    falsePositives: 0,
    totalBenign: 43340,
    truePositives: 1733,
    totalAttacks: 1900,
    rocAuc: 0.9973,
    avgPrecision: 0.9887
  },
  statisticalBaseline: {
    name: "Statistical Baseline",
    type: "Threshold Corroboration Rule",
    accuracy: 97.18,
    precision: 72.72,
    recall: 52.47,
    f1Score: 60.96,
    falsePositiveRate: 0.86,
    falsePositives: 374,
    totalBenign: 43340,
    truePositives: 997,
    totalAttacks: 1900,
    ruleSummary: "Triggers if ≥2 indicators cross thresholds: length ≥ 52, entropy ≥ 4.31, freq ≥ 41, unique subdomains ≥ 41"
  },
  featureImportance: [
    { rank: 1, feature: "entropy", percent: 39.03, description: "Randomness of subdomain label characters" },
    { rank: 2, feature: "subdomain_length", percent: 19.80, description: "Total character count in the subdomain portion" },
    { rank: 3, feature: "query_length", percent: 13.96, description: "Total character length of the full DNS query" },
    { rank: 4, feature: "digit_ratio", percent: 9.01, description: "Proportion of numeric digits in the query" },
    { rank: 5, feature: "longest_label_length", percent: 8.94, description: "Length of the longest dot-separated label" },
    { rank: 6, feature: "special_char_ratio", percent: 5.12, description: "Proportion of hyphens / special characters" },
    { rank: 7, feature: "unique_subdomains", percent: 1.51, description: "Distinct subdomains observed within time window" },
    { rank: 8, feature: "number_of_labels", percent: 1.17, description: "Count of dot-separated components in the domain" },
    { rank: 9, feature: "time_interval", percent: 0.77, description: "Time difference between consecutive client queries" },
    { rank: 10, feature: "query_frequency", percent: 0.70, description: "Number of queries to apex domain in time window" }
  ],
  featureImportanceNote: "Impurity-based global importance from Random Forest. Does not establish causality or explain an individual prediction."
};
