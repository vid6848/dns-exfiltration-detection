#!/usr/bin/env python3
"""
Generate the Comprehensive Project Report PDF for CyberTrace DNS Exfiltration Detection.
Target length: 12-15 pages.
Strictly adheres to verified repository artifacts, reproducible numbers, and audit findings.
"""

import base64
import os
import subprocess
from pathlib import Path
import pypdf

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BRAIN_DIR = Path(r"C:\Users\ADMIN\.gemini\antigravity-ide\brain\5d7daeb5-5936-4cf8-adec-e0c6994e12ea")
EVAL_PLOT_DIR = PROJECT_ROOT / "evaluation" / "results" / "baseline_vs_rf_v1" / "plots"
OUTPUT_HTML = PROJECT_ROOT / "docs" / "project_report.html"
OUTPUT_PDF = PROJECT_ROOT / "CyberTrace_DNS_Exfiltration_Detection_Comprehensive_Project_Report.pdf"

def get_b64(path: Path) -> str:
    if not path.is_file():
        return ""
    return base64.b64encode(path.read_bytes()).decode("utf-8")

# Live dashboard screenshots
img_dashboard = get_b64(BRAIN_DIR / "initial_dashboard_1791781584682.png")
img_benign = get_b64(BRAIN_DIR / "benign_prediction_success_1791782094329.png")
img_attack = get_b64(BRAIN_DIR / "attack_prediction_success_1791782192279.png")
img_batch = get_b64(BRAIN_DIR / "batch_analysis_success_1791782244529.png")
img_benchmarks = get_b64(BRAIN_DIR / "offline_benchmarks_and_features_1791782272940.png")

# Diagnostic evaluation plots
img_metric_cmp = get_b64(EVAL_PLOT_DIR / "metric_comparison.png")
img_fpr_cmp = get_b64(EVAL_PLOT_DIR / "false_positive_rate_comparison.png")
img_cm_rf = get_b64(EVAL_PLOT_DIR / "confusion_matrix_random_forest.png")

raw_html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberTrace DNS Exfiltration Detection — Comprehensive Technical Report</title>
<style>
  @page {
    size: A4;
    margin: 1.3cm 1.2cm 1.3cm 1.2cm;
    @bottom-right {
      content: "Page " counter(page);
      font-size: 7.5pt;
      color: #64748b;
    }
    @bottom-left {
      content: "CyberTrace: DNS Exfiltration Detection Technical Report";
      font-size: 7.5pt;
      color: #64748b;
    }
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.45;
    font-size: 9pt;
    background: #fff;
    margin: 0;
  }
  h1, h2, h3, h4 {
    color: #0f172a;
    font-weight: 700;
  }
  h1 {
    font-size: 19pt;
    margin-bottom: 2px;
    color: #0f172a;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 4px;
  }
  .subtitle {
    font-size: 10pt;
    color: #64748b;
    margin-top: 0;
    margin-bottom: 10px;
    font-weight: 500;
  }
  h2 {
    font-size: 12pt;
    margin-top: 12px;
    margin-bottom: 4px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 2px;
    color: #0369a1;
    page-break-after: avoid;
  }
  h3 {
    font-size: 9.5pt;
    margin-top: 8px;
    margin-bottom: 3px;
    color: #0f172a;
    page-break-after: avoid;
  }
  p, li {
    font-size: 8.5pt;
    margin-top: 2px;
    margin-bottom: 3px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 6px 0 8px 0;
    font-size: 8pt;
    page-break-inside: avoid;
  }
  th, td {
    padding: 4px 6px;
    border: 1px solid #cbd5e1;
    text-align: left;
    vertical-align: top;
  }
  th {
    background-color: #f1f5f9;
    font-weight: 600;
    color: #334155;
  }
  tr:nth-child(even) {
    background-color: #f8fafc;
  }
  .card {
    background: #f8fafc;
    border-left: 3px solid #0284c7;
    padding: 6px 10px;
    margin: 6px 0;
    border-radius: 0 3px 3px 0;
    page-break-inside: avoid;
  }
  .card.alert {
    border-left-color: #ef4444;
    background: #fef2f2;
  }
  .card.warning {
    border-left-color: #f59e0b;
    background: #fffbeb;
  }
  .card.success {
    border-left-color: #10b981;
    background: #f0fdf4;
  }
  code {
    font-family: Consolas, Monaco, "Courier New", monospace;
    font-size: 7.5pt;
    background: #f1f5f9;
    padding: 1px 3px;
    border-radius: 2px;
    color: #0369a1;
  }
  pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 6px 8px;
    border-radius: 3px;
    font-size: 7.5pt;
    font-family: Consolas, Monaco, monospace;
    overflow-x: auto;
    margin: 4px 0 6px 0;
    line-height: 1.35;
  }
  .badge {
    display: inline-block;
    padding: 1px 4px;
    font-size: 7pt;
    font-weight: 600;
    border-radius: 2px;
    text-transform: uppercase;
  }
  .badge-blue { background: #e0f2fe; color: #0369a1; }
  .badge-green { background: #dcfce7; color: #15803d; }
  .badge-red { background: #fee2e2; color: #b91c1c; }
  .badge-amber { background: #fef3c7; color: #92400e; }
  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    padding: 8px;
    border-radius: 4px;
    margin-bottom: 8px;
  }
  .meta-item strong {
    color: #475569;
    font-size: 7pt;
    text-transform: uppercase;
    display: block;
  }
  .meta-item span {
    font-size: 8pt;
    color: #0f172a;
    font-weight: 600;
  }
  .figure-container {
    margin: 6px 0;
    text-align: center;
    page-break-inside: avoid;
  }
  .figure-img {
    max-width: 92%;
    max-height: 200px;
    object-fit: contain;
    border: 1px solid #cbd5e1;
    border-radius: 3px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  .figure-caption {
    font-size: 7pt;
    color: #64748b;
    margin-top: 2px;
    font-style: italic;
  }
  .two-col {
    display: flex;
    gap: 8px;
    page-break-inside: avoid;
    margin: 6px 0;
  }
  .two-col > div {
    flex: 1;
  }
  .page-break {
    page-break-before: always;
  }
</style>
</head>
<body>

<!-- PAGE 1: Overview, Aim & Setup -->
<div>
  <h1>CyberTrace: DNS Exfiltration Detection</h1>
  <p class="subtitle">Complete Technical Project, Architecture, Experiment & Verification Report</p>

  <div class="meta-grid">
    <div class="meta-item"><strong>Repository:</strong> <span>vid6848/dns-exfiltration-detection</span></div>
    <div class="meta-item"><strong>Evaluation Type:</strong> <span>Diagnostic Development Evaluation (Outer Fold 5)</span></div>
    <div class="meta-item"><strong>Evaluated Records:</strong> <span>45,240 records (43,340 Benign, 1,900 Attack)</span></div>
    <div class="meta-item"><strong>Selected Model Artifact:</strong> <span>artifacts/aws_benign_expansion_v0.1/random_forest.joblib</span></div>
    <div class="meta-item"><strong>Calibrated Threshold:</strong> <span>0.89 (FPR = 0.00% on Diagnostic Set)</span></div>
    <div class="meta-item"><strong>Full Stack Implementation:</strong> <span>FastAPI Backend + React 18 / Vite 6 Dashboard</span></div>
  </div>

  <h2>1. Aim and Objectives</h2>
  <p>
  The Domain Name System (DNS) is an indispensable protocol for Internet communications, resolving human-readable hostnames to IP addresses. Because recursive resolvers require unhindered egress via UDP and TCP port 53, perimeter network firewalls rarely restrict or deeply inspect DNS traffic. Consequently, adversaries exploit DNS queries as a covert communication channel for <strong>DNS Tunneling and Data Exfiltration</strong>.
  </p>
  <p>
  In an exfiltration scenario, malicious software encodes confidential payloads (e.g., credentials, files, or telemetry) into the variable subdomain labels of DNS queries directed toward an adversary-controlled authoritative nameserver (e.g. <code>c2a9f1.0f9hzh.attacker-tunnel.live</code>). Recursive resolvers blindly relay these packets, bypassing egress filters.
  </p>
  <div class="card">
  <strong>Core Project Goals:</strong>
  <ol>
    <li><strong>Safe & Leakage-Free Preprocessing:</strong> Build a deterministic schema normalizer that eliminates target labels, IP identifiers, and raw timestamps from model training inputs.</li>
    <li><strong>Rigorous Feature Engineering:</strong> Implement exactly 7 structural per-query features and 3 sliding-window behavioral features based on domain length, entropy, and temporal repetition.</li>
    <li><strong>Empirical Detection Comparison:</strong> Benchmark a frozen 4-indicator statistical baseline rule against an ensemble Random Forest classifier using domain-disjoint cross-validation.</li>
    <li><strong>Generalization Diagnosis:</strong> Diagnose and resolve enterprise false positives caused by complex benign cloud infrastructure (e.g., AWS EC2 subdomains).</li>
    <li><strong>Production Full-Stack Serving:</strong> Expose real-time inference via an asynchronous FastAPI backend and an interactive React dashboard with automated regression test suites.</li>
  </ol>
  </div>

  <h2>2. Environment and Setup</h2>
  <p>
  The project is implemented in a cross-platform Python and Node.js environment with minimal third-party dependencies to ensure high execution speed and reproducibility:
  </p>
  <ul>
    <li><strong>Core Runtime:</strong> Python 3.10+ (tested on Python 3.14 on Windows/Linux) and Node.js 18+ (npm 10+).</li>
    <li><strong>Backend & ML Libraries:</strong> FastAPI (<code>0.115+</code>), Uvicorn (<code>0.34+</code>), Scikit-learn (<code>1.5+</code>), Joblib (<code>1.4+</code>), Pydantic (<code>2.10+</code>), Pytest (<code>8.3+</code>).</li>
    <li><strong>Frontend Stack:</strong> React 18 (<code>18.3.1</code>), Vite (<code>6.0.1</code>), custom Vanilla CSS (design tokens, responsive dark-accent cards).</li>
    <li><strong>Repository Layout:</strong>
      <code>api/</code> (REST endpoints), 
      <code>src/preprocessing/</code> (parsing & schema), 
      <code>src/features/</code> (lexical & behavioral extractors), 
      <code>src/baseline/</code> (statistical detector), 
      <code>src/ml/</code> (training & model bundles), 
      <code>frontend/</code> (React UI), 
      <code>evaluation/</code> (metrics & plots), 
      <code>tests/</code> (automated test suite).
    </li>
  </ul>
</div>

<div class="page-break"></div>

<!-- PAGE 2: Team Attribution -->
<div>
  <h2>3. Comprehensive Team Attribution: Who Did What</h2>
  <p>
  The CyberTrace detection pipeline was developed through coordinated specialization across data engineering, modeling, evaluation, and system integration. All contributions reflect verified commits and code artifacts:
  </p>

  <table>
    <thead>
      <tr>
        <th style="width: 16%;">Contributor</th>
        <th style="width: 24%;">Assigned Area</th>
        <th>Key Deliverables & Verified Repository Contributions</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Vidhi</strong><br><span class="badge badge-blue">Project Lead</span></td>
        <td>Repository Architecture & Benign Data Expansion</td>
        <td>
          • Architected the base repository structure, documentation roadmaps, and PR workflows.<br>
          • Identified the critical "unseen benign data" distribution shift where AWS EC2 domains triggered false alarms.<br>
          • Built the public benign PCAP expansion pipeline (<code>scripts/import_public_benign.py</code>, <code>docs/public_benign_data_research.md</code>).
        </td>
      </tr>
      <tr>
        <td><strong>Param</strong><br><span class="badge badge-blue">Dataset Eng.</span></td>
        <td>Simulated Attack Dataset Generation</td>
        <td>
          • Designed and authored the synthetic attack generator: <code>data/generate_synthetic_exfiltration.py</code>.<br>
          • Built the strict 10-column schema validator: <code>data/validate_synthetic.py</code>.<br>
          • Generated 10,000 diverse attack records across Base32/Base64, hex chunks, burst queries, and drip tunneling.<br>
          • Authored comprehensive methodology documentation in <code>data/synthetic_generation.md</code>.
        </td>
      </tr>
      <tr>
        <td><strong>Yash</strong><br><span class="badge badge-blue">Data Pipeline</span></td>
        <td>Preprocessing, Parsing & Leakage Elimination</td>
        <td>
          • Implemented the complete <code>src/preprocessing/</code> module (<code>parser.py</code>, <code>normalizer.py</code>, <code>pipeline.py</code>, <code>schema.py</code>).<br>
          • Guaranteed strict data-leakage elimination: stripped target labels, timestamps, and IP addresses before feature extraction.<br>
          • Produced the validated unified training dataset: <code>data/processed/cleaned_unified_v0.1.csv</code> (109,989 total records).
        </td>
      </tr>
      <tr>
        <td><strong>Rudraksh</strong><br><span class="badge badge-blue">Baseline Eng.</span></td>
        <td>Statistical Detection Baseline</td>
        <td>
          • Implemented the rule-based baseline detector: <code>src/baseline/detector.py</code> and <code>src/baseline/evaluate_baseline.py</code>.<br>
          • Engineered the 4-indicator corroborated scoring rule (length, entropy, frequency, unique subdomains).<br>
          • Established the scientific baseline benchmark demonstrating machine learning's necessity in minimizing false alarms.
        </td>
      </tr>
      <tr>
        <td><strong>Jaynish</strong><br><span class="badge badge-blue">ML Engineer</span></td>
        <td>Machine Learning Training & Group CV</td>
        <td>
          • Developed model training workflows: <code>src/ml/train.py</code>, <code>src/ml/artifact.py</code>, and <code>src/ml/group_cv.py</code>.<br>
          • Enforced domain-disjoint group cross-validation by apex domain to prevent memorization and data leakage.<br>
          • Produced model artifacts <code>random_forest_v0.1</code> and <code>random_forest_v0.2</code> with balanced class weights and threshold calibration.
        </td>
      </tr>
      <tr>
        <td><strong>Harshul</strong><br><span class="badge badge-blue">Research Analyst</span></td>
        <td>Model Evaluation, Latency & Research Analysis</td>
        <td>
          • Conducted the formal comparative analysis: <code>scripts/evaluate_baseline_vs_rf.py</code> and <code>evaluation_report.md</code>.<br>
          • Measured execution latencies: <code>scripts/benchmark_evaluation_latency.py</code> (45.7 &mu;s/query for Random Forest).<br>
          • Generated publication plots and feature importance figures in <code>evaluation/results/baseline_vs_rf_v1/</code>.
        </td>
      </tr>
      <tr>
        <td><strong>Pranay</strong><br><span class="badge badge-blue">Backend Lead</span></td>
        <td>FastAPI Production Serving & Behavioral Extractor</td>
        <td>
          • Implemented the REST API in <code>api/main.py</code> serving <code>/health</code>, <code>/predict</code>, and <code>/analyze</code>.<br>
          • Integrated the sliding-window behavioral extractor with chronologically sorted multi-query batch history.<br>
          • Added CORS middleware and authored the automated API test suite in <code>tests/test_api.py</code> (11 passed tests).
        </td>
      </tr>
      <tr>
        <td><strong>Bhumit</strong><br><span class="badge badge-blue">Frontend Lead</span></td>
        <td>React Dashboard & Client Integration</td>
        <td>
          • Built the React 18 single-page application in <code>frontend/src/</code> with Vite 6 and custom component CSS.<br>
          • Designed real-time prediction forms, sample query pre-loaders, latency telemetry, and batch risk tables.<br>
          • Authored the frontend client test suite in <code>frontend/src/api/client.test.js</code> (6 passed tests).
        </td>
      </tr>
    </tbody>
  </table>
</div>

<div class="page-break"></div>

<!-- PAGE 3: Dataset Preparation -->
<div>
  <h2>4. Dataset Preparation and Preprocessing Pipeline</h2>
  <p>
  A primary failure mode in network intrusion detection research is synthetic dataset leakage and class representation bias. The CyberTrace pipeline established a strict multi-stage ingestion and validation workflow:
  </p>

  <h3>4.1 Data Sources & Synthesis</h3>
  <ul>
    <li><strong>Mendeley DNS Exfiltration Capture (Raw Benign):</strong> Ingested from <code>data/raw/dataset_dns_exfiltration.csv</code>, comprising 109,359 captured queries from enterprise network environments.</li>
    <li><strong>Param's Synthetic Attack Generation (10,000 Queries):</strong> Generated via <code>data/generate_synthetic_exfiltration.py</code> using verified exfiltration patterns:
      <ul>
        <li><em>Encoding schemes:</em> Base32, Base64, and hexadecimal chunks reflecting tools such as <code>iodine</code> and <code>dnscat2</code>.</li>
        <li><em>Subdomain chunking:</em> Variable label lengths (15 to 45 characters) concatenated across 3 to 7 labels.</li>
        <li><em>Temporal pacing:</em> Fast burst exfiltration (multiple queries/sec) and stealthy slow-drip pacing (randomized 5–60s delays).</li>
      </ul>
    </li>
    <li><strong>Public Benign PCAP Expansion (85,604 Queries):</strong> Extracted from publisher-labeled university campus traffic (<code>scripts/import_public_benign.py</code>) to expose the model to diverse cloud infrastructure patterns.</li>
  </ul>

  <h3>4.2 Verified Dataset Populations</h3>
  <table>
    <thead>
      <tr>
        <th>Dataset File</th>
        <th>Total Records</th>
        <th>Benign Count</th>
        <th>Attack Count</th>
        <th>Role in Pipeline</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>data/raw/dataset_dns_exfiltration.csv</code></td>
        <td>109,359</td>
        <td>99,989</td>
        <td>9,370 (legacy)</td>
        <td>Original raw Mendeley capture baseline.</td>
      </tr>
      <tr>
        <td><code>data/processed/synthetic_exfiltration_v0.1.csv</code></td>
        <td>10,000</td>
        <td>0</td>
        <td>10,000</td>
        <td>Synthetic exfiltration records generated by Param.</td>
      </tr>
      <tr>
        <td><code>data/processed/benign_dns_v0.1.csv</code></td>
        <td>99,989</td>
        <td>99,989</td>
        <td>0</td>
        <td>Normalized benign enterprise queries.</td>
      </tr>
      <tr>
        <td><code>data/processed/cleaned_unified_v0.1.csv</code></td>
        <td><strong>109,989</strong></td>
        <td>99,989</td>
        <td>10,000</td>
        <td>Primary unified dataset after schema normalization.</td>
      </tr>
      <tr>
        <td><strong>Diagnostic Evaluation Population</strong></td>
        <td><strong>45,240</strong></td>
        <td>43,340</td>
        <td>1,900</td>
        <td>Outer fold 5 diagnostic set (includes 36,255 AWS records).</td>
      </tr>
    </tbody>
  </table>

  <h3>4.3 Normalization & Leakage Elimination</h3>
  <p>
  Implemented in <code>src/preprocessing/pipeline.py</code> and verified by <code>verify_ml_feature_safety()</code>:
  </p>
  <ol>
    <li><strong>Stripping Target Labels & Identifiers:</strong> Ground-truth binary labels, source IPs, destination IPs, and database row IDs are strictly excluded from the feature matrix X.</li>
    <li><strong>FQDN Normalization:</strong> Strips trailing root dots, lowercases characters, and segments domains into apex domain and subdomains using Public Suffix List rules.</li>
    <li><strong>Temporal Separation:</strong> Timestamps are used solely for sliding-window delta calculations (&Delta;t) and are never fed directly as numerical features.</li>
  </ol>
</div>

<div class="page-break"></div>

<!-- PAGE 4: Feature Engineering -->
<div>
  <h2>5. Feature Engineering Contract</h2>
  <p>
  The system enforces an exact, ordered ten-feature contract (<code>FEATURE_ORDER</code> in <code>src/ml/features.py</code>). All features are strictly deterministic and numerical:
  </p>

  <table>
    <thead>
      <tr>
        <th style="width: 22%;">Feature Name</th>
        <th style="width: 14%;">Category</th>
        <th style="width: 14%;">Importance</th>
        <th>Mathematical Formula & Security Rationale</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>entropy</code></td>
        <td>Lexical (FQDN)</td>
        <td><strong>38.99%</strong></td>
        <td>
          Shannon entropy over full query: H = -&Sigma; (p_i &times; log2(p_i)).<br>
          Exfiltration encodings (Base64/hex) exhibit high entropy (&gt; 4.0), while benign domains average &lt; 3.2.
        </td>
      </tr>
      <tr>
        <td><code>subdomain_length</code></td>
        <td>Lexical</td>
        <td><strong>17.84%</strong></td>
        <td>
          Total character count of all prepended subdomain labels.<br>
          Tunnels maximize payload capacity per query (often &gt; 35 characters).
        </td>
      </tr>
      <tr>
        <td><code>query_length</code></td>
        <td>Lexical</td>
        <td><strong>14.85%</strong></td>
        <td>
          Total length of the Fully Qualified Domain Name (FQDN) string (capped at RFC 1035 limit of 253 octets).
        </td>
      </tr>
      <tr>
        <td><code>digit_ratio</code></td>
        <td>Lexical</td>
        <td><strong>9.54%</strong></td>
        <td>
          Ratio of numeric characters: count(digits) / query_length.<br>
          Base32 and hexadecimal exfiltration streams sharply elevate numeric density.
        </td>
      </tr>
      <tr>
        <td><code>longest_label_length</code></td>
        <td>Lexical</td>
        <td><strong>8.79%</strong></td>
        <td>
          Length of the longest dot-separated label. Tunnels pack up to 63 bytes per DNS label.
        </td>
      </tr>
      <tr>
        <td><code>special_char_ratio</code></td>
        <td>Lexical</td>
        <td><strong>6.13%</strong></td>
        <td>
          Proportion of non-alphanumeric characters: count(non-alphanumeric) / query_length (e.g., dots, hyphens, underscores).
        </td>
      </tr>
      <tr>
        <td><code>time_interval</code></td>
        <td>Behavioral</td>
        <td><strong>1.46%</strong></td>
        <td>
          Elapsed time in seconds since the previous query from the same (src_ip, apex_domain). Set to -1.0 for initial queries.
        </td>
      </tr>
      <tr>
        <td><code>number_of_labels</code></td>
        <td>Lexical</td>
        <td><strong>1.20%</strong></td>
        <td>
          Count of dot-delimited segments in the domain name. Multi-stage chunking increases label count.
        </td>
      </tr>
      <tr>
        <td><code>unique_subdomains</code></td>
        <td>Behavioral</td>
        <td><strong>0.74%</strong></td>
        <td>
          Distinct subdomains requested under the same (src_ip, apex_domain) within a 60.0-second sliding temporal window.
        </td>
      </tr>
      <tr>
        <td><code>query_frequency</code></td>
        <td>Behavioral</td>
        <td><strong>0.46%</strong></td>
        <td>
          Total number of DNS requests sent by the client to the same apex domain within the 60.0-second sliding window.
        </td>
      </tr>
    </tbody>
  </table>

  <div class="card">
  <strong>Behavioral Sliding Window Implementation (<code>src/features/behavioral.py</code>):</strong><br>
  Calculated incrementally across incoming queries using an inclusive window: t in [t_current - 60.0, t_current]. Query history is tracked per (src_ip, apex_domain) pair. IP addresses and raw timestamps are strictly discarded once window grouping is established.
  </div>
</div>

<div class="page-break"></div>

<!-- PAGE 5: Detection Models & Training -->
<div>
  <h2>6. Detection Models: Statistical Baseline vs. Random Forest</h2>

  <h3>6.1 Statistical Threshold Baseline (Rudraksh)</h3>
  <p>
  The baseline detector (<code>src/baseline/detector.py</code>) provides an explainable, non-ML reference standard using four corroborated indicator thresholds frozen from engineering handoff:
  </p>
  <pre>
# Frozen Baseline Threshold Rules (src/baseline/detector.py)
query_length >= 52.0
entropy >= 4.309101
query_frequency >= 41.0
unique_subdomains >= 41.0
Condition: Flagged as SUSPICIOUS if at least TWO indicators cross threshold simultaneously.
  </pre>
  <p>
  By requiring corroborated flags (&ge; 2), the baseline avoids triggering on isolated spikes in query length. However, it cannot learn non-linear boundaries between complex features.
  </p>

  <h3>6.2 Random Forest Classifier Architecture (Jaynish)</h3>
  <p>
  The production classifier is an ensemble Random Forest (<code>src/ml/train.py</code>) designed for robustness and low latency:
  </p>
  <ul>
    <li><strong>Hyperparameters:</strong> 150 decision trees, <code>max_depth=12</code>, <code>min_samples_leaf=5</code>, <code>max_features="sqrt"</code>, <code>class_weight=None</code>, random seed 42.</li>
    <li><strong>Domain-Disjoint Group K-Fold Splitting:</strong> Data is split strictly by <code>apex_domain</code>. All queries belonging to an apex domain reside exclusively within train, validation, or test. This prevents the model from memorizing known domains.</li>
    <li><strong>Calibrated Decision Threshold (&tau; = 0.89):</strong> Instead of an arbitrary 0.5 threshold, the operating threshold was calibrated against development partitions to enforce pooled FPR &le; 1.0% and cloud domain FPR &le; 5.0%.</li>
    <li><strong>Deterministic Inference:</strong> Training uses multi-threaded parallel fitting, but artifact inference locks <code>n_jobs=1</code> to ensure bit-for-bit reproducible probability sums across platforms.</li>
  </ul>

  <h3>6.3 Reproducible Training and Evaluation Commands</h3>
  <pre>
# Run domain-disjoint group cross-validation training:
python -m src.ml.train --dataset data/processed/cleaned_unified_v0.1.csv

# Execute empirical evaluation comparing Baseline vs Random Forest:
python scripts/evaluate_baseline_vs_rf.py
  </pre>
</div>

<div class="page-break"></div>

<!-- PAGE 6: Experiments and Results & Discrepancy Resolution -->
<div>
  <h2>7. Experiments, Results, and Resolution of Metrics</h2>

  <h3>7.1 Diagnostic Development Evaluation Results (45,240 Records)</h3>
  <p>
  Both detectors were evaluated on the exact 45,240 diagnostic records in <code>evaluation/results/baseline_vs_rf_v1/baseline_vs_rf_metrics.json</code> (comprising 43,340 benign records and 1,900 simulated attacks):
  </p>

  <table>
    <thead>
      <tr>
        <th>Performance Metric</th>
        <th>Statistical Baseline</th>
        <th>Random Forest (&tau; = 0.89)</th>
        <th>Operational Comparison</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Accuracy</strong></td>
        <td>97.18%</td>
        <td><strong>99.60%</strong></td>
        <td>+2.42% overall accuracy improvement.</td>
      </tr>
      <tr>
        <td><strong>Precision</strong></td>
        <td>72.72%</td>
        <td><strong>100.00%</strong></td>
        <td>Zero false alarms on diagnostic set.</td>
      </tr>
      <tr>
        <td><strong>Recall (Sensitivity)</strong></td>
        <td>52.47%</td>
        <td><strong>90.53%</strong></td>
        <td>+38.06% increase in detected attack queries.</td>
      </tr>
      <tr>
        <td><strong>F1-Score</strong></td>
        <td>0.6096 (60.96%)</td>
        <td><strong>0.9503 (95.03%)</strong></td>
        <td>Near-optimal harmonic mean.</td>
      </tr>
      <tr>
        <td><strong>False Positive Rate (FPR)</strong></td>
        <td>0.8629% (374 false alarms)</td>
        <td><strong>0.0000% (0 false alarms)</strong></td>
        <td>Complete elimination of false alarms on evaluated records.</td>
      </tr>
      <tr>
        <td><strong>True Positives (TP)</strong></td>
        <td>997 / 1,900</td>
        <td><strong>1,720 / 1,900</strong></td>
        <td>Detected 723 additional exfiltration queries.</td>
      </tr>
      <tr>
        <td><strong>False Negatives (FN)</strong></td>
        <td>903 / 1,900</td>
        <td><strong>180 / 1,900</strong></td>
        <td>Reduced missed attacks from 903 to 180.</td>
      </tr>
      <tr>
        <td><strong>ROC-AUC / Avg Precision</strong></td>
        <td>N/A (Rule-based)</td>
        <td><strong>0.9978 / 0.9879</strong></td>
        <td>Exceptional ranking separation across threshold spectrum.</td>
      </tr>
      <tr>
        <td><strong>Inference Latency</strong></td>
        <td>12.4 &mu;s / query</td>
        <td><strong>45.7 &mu;s / query</strong></td>
        <td>Processes 21,881 queries/sec on a single CPU core.</td>
      </tr>
    </tbody>
  </table>

  <div class="card warning">
  <strong>Critical Resolution of Conflicting Evaluation Figures:</strong><br>
  A prior draft of this report stated an unverified test metric of <em>F1 = 99.98% and FPR = 0.04% on 40,000 queries</em>. Cross-referencing committed project artifacts reveals the actual experimental progression:
  <ol>
    <li><strong>Initial Model Failure (v0.1 Holdout):</strong> The initial RF model (<code>artifacts/random_forest_v0.1</code>) was tested on 38,155 held-out queries where benign traffic consisted of <code>amazonaws.com</code>. Because AWS EC2 subdomains are long and high in entropy, the initial model produced an <strong>FPR of 99.62%</strong> (flagging 36,117 benign queries) and an <strong>F1 of only 9.52%</strong>.</li>
    <li><strong>Public Benign Expansion & Calibration:</strong> Vidhi expanded benign development data with public PCAP traffic (<code>artifacts/aws_benign_expansion_v0.1</code>) and re-calibrated the threshold to <strong>0.89</strong> to accommodate cloud naming structures.</li>
    <li><strong>Verified Diagnostic Result:</strong> Evaluated against the 45,240 diagnostic development records (including 36,255 AWS records), the updated model achieved <strong>F1 = 95.03%</strong> and <strong>FPR = 0.00%</strong> (1,720 TP, 43,340 TN, 0 FP, 180 FN).</li>
    <li><strong>Scientific Scope:</strong> These figures are from a <em>diagnostic development evaluation</em> (outer fold 5), <strong>not</strong> an independent final test on fresh, live production traffic.</li>
  </ol>
  </div>
</div>

<div class="page-break"></div>

<!-- PAGE 7: Empirical Plots & Feature Importance -->
<div>
  <h2>7.2 Empirical Visualizations & Feature Importance Distribution</h2>
  <p>
  The evaluation suite generated publication-grade visualizations in <code>evaluation/results/baseline_vs_rf_v1/plots/</code>:
  </p>

  <div class="two-col">
    <div>
      <div class="figure-container">
        <img class="figure-img" src="data:image/png;base64,{{IMG_METRIC_CMP}}" alt="Metric Comparison" />
        <div class="figure-caption">Figure 7.1: Metric Comparison (Baseline vs. Random Forest) showing significant recall and F1 gains.</div>
      </div>
    </div>
    <div>
      <div class="figure-container">
        <img class="figure-img" src="data:image/png;base64,{{IMG_FPR_CMP}}" alt="FPR Comparison" />
        <div class="figure-caption">Figure 7.2: False Positive Rate Comparison demonstrating total elimination of false alarms on diagnostic set.</div>
      </div>
    </div>
  </div>

  <div class="two-col">
    <div style="flex: 1.1;">
      <h3>Gini Feature Importance Ranking</h3>
      <p>Impurity-based global feature importances extracted from <code>feature_importance.json</code>:</p>
      <table>
        <thead>
          <tr>
            <th>Rank</th>
            <th>Feature</th>
            <th>Weight</th>
            <th>Primary Role</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>1</td><td><code>entropy</code></td><td><strong>38.99%</strong></td><td>Measures encoded randomness</td></tr>
          <tr><td>2</td><td><code>subdomain_length</code></td><td><strong>17.84%</strong></td><td>Detects large data payloads</td></tr>
          <tr><td>3</td><td><code>query_length</code></td><td><strong>14.85%</strong></td><td>Captures overall packet sizing</td></tr>
          <tr><td>4</td><td><code>digit_ratio</code></td><td><strong>9.54%</strong></td><td>Identifies hex/base32 density</td></tr>
          <tr><td>5</td><td><code>longest_label_length</code></td><td><strong>8.79%</strong></td><td>Flags packed tunnel chunks</td></tr>
          <tr><td>6</td><td><code>special_char_ratio</code></td><td><strong>6.13%</strong></td><td>Separates label delimiters</td></tr>
          <tr><td>7</td><td><code>time_interval</code></td><td><strong>1.46%</strong></td><td>Tracks temporal query pacing</td></tr>
          <tr><td>8</td><td><code>number_of_labels</code></td><td><strong>1.20%</strong></td><td>Flags multi-level chunking</td></tr>
          <tr><td>9</td><td><code>unique_subdomains</code></td><td><strong>0.74%</strong></td><td>Tracks behavioral variation</td></tr>
          <tr><td>10</td><td><code>query_frequency</code></td><td><strong>0.46%</strong></td><td>Measures request burstiness</td></tr>
        </tbody>
      </table>
    </div>
    <div style="flex: 0.9;">
      <div class="figure-container" style="margin-top: 10px;">
        <img class="figure-img" src="data:image/png;base64,{{IMG_CM_RF}}" alt="Random Forest Confusion Matrix" />
        <div class="figure-caption">Figure 7.3: Confusion Matrix for Random Forest (43,340 TN, 1,720 TP, 0 FP, 180 FN).</div>
      </div>
    </div>
  </div>
</div>

<div class="page-break"></div>

<!-- PAGE 8: Backend & Frontend Architecture -->
<div>
  <h2>8. Backend and Frontend System Architecture</h2>
  <p>
  The CyberTrace platform integrates model inference with an asynchronous serving backend and a reactive dashboard client:
  </p>

  <h3>8.1 End-to-End Ingestion and Detection Pipeline Flow</h3>
  <div class="card">
  <strong>Pipeline Lifecycle:</strong>
  <ol>
    <li><strong>DNS Query Ingestion:</strong> The client sends query metadata (timestamp, source IP, destination IP, requested server name) via <code>POST /predict</code> or <code>POST /analyze</code>.</li>
    <li><strong>Preprocessing & Normalization:</strong> <code>PreprocessingPipeline</code> normalizes the FQDN, extracts the apex domain and subdomain labels, and validates RFC formatting.</li>
    <li><strong>Feature Extraction:</strong>
      <ul>
        <li><code>extract_per_query_features()</code> computes the 7 lexical metrics.</li>
        <li><code>BehavioralFeatureExtractor</code> computes the 3 sliding-window metrics using temporal client history.</li>
      </ul>
    </li>
    <li><strong>Model Evaluation:</strong> The 10 features are formatted into the canonical feature matrix and evaluated by the Random Forest model bundle.</li>
    <li><strong>Decision Thresholding:</strong> The calculated probability is compared against &tau; = 0.89. The endpoint outputs classification verdict (<code>benign</code> vs <code>suspicious</code>), confidence percentage, and inference latency.</li>
    <li><strong>User Interface Presentation:</strong> The React dashboard displays visual threat banners, color-coded risk bars, and aggregate telemetry.</li>
  </ol>
  </div>

  <h3>8.2 API Serving Architecture (Pranay)</h3>
  <ul>
    <li><strong>FastAPI Asynchronous Engine (<code>api/main.py</code>):</strong> Loads the model artifact once at startup within an asynchronous lifespan context.</li>
    <li><strong>CORS Support:</strong> Integrated <code>CORSMiddleware</code> allowing local frontend development origins (<code>http://localhost:3000</code>).</li>
    <li><strong>Batch Behavioral State Accumulation:</strong> In <code>POST /analyze</code>, queries are sorted chronologically, processed through a shared sliding-window extractor, and restored to original array index order.</li>
  </ul>

  <h3>8.3 Security Dashboard Architecture (Bhumit)</h3>
  <ul>
    <li><strong>Modular React Components:</strong> Built with clean functional components: <code>Navbar</code>, <code>SingleQueryForm</code>, <code>BatchAnalysisSection</code>, and <code>OfflineEvaluationSection</code>.</li>
    <li><strong>Live Heartbeat Telemetry:</strong> Periodically polls <code>GET /health</code> to display live API connectivity and model status.</li>
    <li><strong>Zero-Dependency Design System:</strong> Custom CSS tokens implementing dark-accent cards, emerald benign pills, red alert banners, and risk progress bars.</li>
  </ul>
</div>

<div class="page-break"></div>

<!-- PAGE 9: Visual Verification - Dashboard & Single Query -->
<div>
  <h2>9. Interactive Web Application Verification (Dashboard & API)</h2>
  <p>
  The application was verified running live at <code>http://localhost:3000/</code> with FastAPI at <code>http://127.0.0.1:8000/</code>:
  </p>

  <h3>9.1 Dashboard Overview & Live Backend Heartbeat</h3>
  <p>
  Upon loading, the interface verifies that the machine learning model is loaded in memory and healthy via <code>GET /health</code>:
  </p>
  <div class="figure-container">
    <img class="figure-img" src="data:image/png;base64,{{IMG_DASHBOARD}}" alt="Dashboard Initial Overview" style="max-height: 220px;" />
    <div class="figure-caption">Figure 9.1: CyberTrace Unified Dashboard showing live API connectivity badge, navigation bar, and Single Query Inspection form.</div>
  </div>

  <h3>9.2 Single Query Evaluation: Normal Benign Traffic vs Exfiltration Attack</h3>
  <div class="two-col">
    <div>
      <div class="figure-container">
        <img class="figure-img" src="data:image/png;base64,{{IMG_BENIGN}}" alt="Benign Prediction Result" style="max-height: 180px;" />
        <div class="figure-caption">Figure 9.2: Single Query Evaluation of <code>api.github.com</code> yielding emerald <code>✅ BENIGN</code> status (0.00% anomaly score, 2.1 ms latency).</div>
      </div>
    </div>
    <div>
      <div class="figure-container">
        <img class="figure-img" src="data:image/png;base64,{{IMG_ATTACK}}" alt="Attack Prediction Result" style="max-height: 180px;" />
        <div class="figure-caption">Figure 9.3: Active exfiltration detection on encoded payload yielding <code>🚨 SUSPICIOUS</code> warning (94.27% attack score, 3.4 ms latency).</div>
      </div>
    </div>
  </div>
</div>

<div class="page-break"></div>

<!-- PAGE 10: Visual Verification - Batch & Benchmarks -->
<div>
  <h2>9.3 Batch Query Stream & Behavioral Traffic Analysis</h2>
  <p>
  Analysts can submit multi-query DNS logs. The system computes temporal sliding-window features, updates aggregate summary statistics, and generates an itemized threat assessment table:
  </p>
  <div class="figure-container">
    <img class="figure-img" src="data:image/png;base64,{{IMG_BATCH}}" alt="Batch Analysis Results" style="max-height: 220px;" />
    <div class="figure-caption">Figure 9.4: Batch stream analysis displaying total analyzed count (4), benign count (2), suspicious count (2), and itemized risk progress bars.</div>
  </div>

  <h3>9.4 Offline Model Performance Benchmarks in Dashboard</h3>
  <p>
  The dashboard embeds verified diagnostic benchmark figures directly from project artifacts, allowing analysts to review baseline comparisons and feature weights:
  </p>
  <div class="figure-container">
    <img class="figure-img" src="data:image/png;base64,{{IMG_BENCHMARKS}}" alt="Offline Benchmarks and Feature Importance" style="max-height: 220px;" />
    <div class="figure-caption">Figure 9.5: Embedded offline evaluation comparison table and Gini feature importance breakdown (entropy leading at 38.99%).</div>
  </div>
</div>

<div class="page-break"></div>

<!-- PAGE 11: Verification Audit & Testing -->
<div>
  <h2>10. Testing, Verification, and Audit History</h2>

  <h3>10.1 Verified Audit Remediations</h3>
  <p>
  An end-to-end audit of Pranay's backend and Bhumit's frontend identified and resolved four critical integration issues:
  </p>
  <table>
    <thead>
      <tr>
        <th>Component</th>
        <th>Identified Defect</th>
        <th>Remediation Applied</th>
        <th>Verification Status</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Backend</strong></td>
        <td>Missing CORS middleware in <code>api/main.py</code>, causing browser requests from port 3000 to be blocked.</td>
        <td>Configured FastAPI <code>CORSMiddleware</code> with environment-configurable origins.</td>
        <td><span class="badge badge-green">Preflight 200 OK</span></td>
      </tr>
      <tr>
        <td><strong>Backend</strong></td>
        <td>Behavioral extractor recreated on every query inside <code>/analyze</code> loop, discarding temporal history.</td>
        <td>Instantiated single batch extractor, sorted queries chronologically, and restored original index order.</td>
        <td><span class="badge badge-green">History Verified</span></td>
      </tr>
      <tr>
        <td><strong>Backend</strong></td>
        <td>Lack of automated regression test suite for API endpoints.</td>
        <td>Created <code>tests/test_api.py</code> covering routes, validation errors, and health checks.</td>
        <td><span class="badge badge-green">11 / 11 Passed</span></td>
      </tr>
      <tr>
        <td><strong>Frontend</strong></td>
        <td>Client lacked automated unit testing.</td>
        <td>Added native <code>node --test</code> suite in <code>frontend/src/api/client.test.js</code>.</td>
        <td><span class="badge badge-green">6 / 6 Passed</span></td>
      </tr>
    </tbody>
  </table>

  <h3>10.2 Automated Test Suite Results</h3>
  <ul>
    <li><strong>Backend Test Suite (<code>pytest tests/</code>):</strong>
      <pre>
============ 75 passed, 1 skipped, 2 warnings in 68.97s ============
tests/test_api.py ........... (11 passed)
tests/test_aws_generalization.py ... (3 passed)
tests/test_baseline_detector.py ....... (7 passed)
tests/test_behavioral_features.py ...... (6 passed)
tests/test_ml_training.py ........ (8 passed)
tests/test_per_query_features.py ........... (11 passed)
tests/test_preprocessing.py ..................... (21 passed)
tests/test_robust_training.py ........ (8 passed)
      </pre>
    </li>
    <li><strong>Frontend Client Suite (<code>npm test</code>):</strong>
      <pre>
ℹ tests 6 | pass 6 | fail 0 | duration_ms 593.5ms
✔ API Client Tests (health check, single prediction, batch analysis, error handling)
      </pre>
    </li>
    <li><strong>Frontend Production Build:</strong> Verified via <code>npm run build</code>; compiled clean Vite production bundle in 2.23 seconds with zero lint or packaging errors.</li>
  </ul>
</div>

<div class="page-break"></div>

<!-- PAGE 12: Reproducibility & Quickstart -->
<div>
  <h2>11. Reproducibility: Minimum Operational Commands</h2>
  <p>
  The complete CyberTrace pipeline can be verified and executed from scratch using the following commands:
  </p>

  <h3>Step 1: Environment Setup</h3>
  <pre>
# Clone repository and install Python dependencies:
git clone https://github.com/vid6848/dns-exfiltration-detection.git
cd dns-exfiltration-detection
pip install -r requirements.txt

# Install frontend dependencies:
cd frontend
npm ci
cd ..
  </pre>

  <h3>Step 2: Run Verification Test Suites</h3>
  <pre>
# Run full backend test suite (75 tests):
python -m pytest tests/

# Run frontend client tests (6 tests):
cd frontend && npm test && cd ..
  </pre>

  <h3>Step 3: Reproduce Model Evaluation & Latency Benchmarks</h3>
  <pre>
# Run baseline vs Random Forest diagnostic evaluation:
python scripts/evaluate_baseline_vs_rf.py

# Run latency benchmark suite:
python scripts/benchmark_evaluation_latency.py
  </pre>

  <h3>Step 4: Launch Full Stack on Localhost</h3>
  <pre>
# Terminal 1 - Start FastAPI Backend (Port 8000):
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 - Start React Dashboard (Port 3000):
cd frontend
npm run dev
  </pre>

  <h3>Step 5: Interactive Verification</h3>
  <ul>
    <li>Open <code>http://localhost:3000/</code> in any modern web browser.</li>
    <li>Verify green "API: Online" status indicator.</li>
    <li>Click "Benign Sample" &rarr; "Run Prediction" &rarr; Confirm emerald <code>✅ BENIGN</code> result (0.00% attack score).</li>
    <li>Input attack domain <code>73w6qw6ehb.0f9hzhj3lvgfo.fc5638.edge-cdn-beacon.live</code> &rarr; Confirm <code>🚨 SUSPICIOUS</code> result (&gt;90% attack score).</li>
    <li>Click "Load Sample Batch" &rarr; "Analyze Batch" &rarr; Confirm batch metrics and table risk bars.</li>
  </ul>
</div>

<div class="page-break"></div>

<!-- PAGE 13: Limitations, Roadmap & Conclusion -->
<div>
  <h2>12. Scope Limitations, Unimplemented Capabilities & Future Roadmap</h2>
  <p>
  In the interest of scientific rigor and operational clarity, the boundaries of the current implementation are explicitly defined:
  </p>

  <h3>12.1 Explicit System Limitations</h3>
  <ul>
    <li><strong>Continuous Packet Capture (PCAP Sniffing) Not Implemented:</strong> The current system does not include a background packet capture daemon (e.g., using Scapy or libpcap to sniff port 53). Ingestion is currently performed via JSON payloads sent to REST API endpoints.</li>
    <li><strong>Continuous Live Streaming Alerts Not Implemented:</strong> Roadmap endpoints such as <code>/alerts</code> and <code>/statistics</code> for continuous WebSocket push notifications have not been deployed in this release.</li>
    <li><strong>Plaintext DNS Visibility Prerequisite:</strong> The structural feature extractor requires plaintext DNS hostnames. Encrypted DNS protocols (DNS-over-HTTPS / DNS-over-TLS) blind lexical analysis unless decrypted at an enterprise recursive resolver.</li>
    <li><strong>Diagnostic Development Scope:</strong> Reported metrics (95.03% F1, 0.00% FPR) are derived from the 45,240 diagnostic development records. While representative of AWS cloud domains and synthetic attacks, they do not guarantee zero false alarms on unobserved real-world network traffic.</li>
  </ul>

  <h3>12.2 Future Roadmap</h3>
  <ol>
    <li><strong>Live Packet Sniffing Daemon:</strong> Integrate a modular C++/Python packet sniffer reading raw interface sockets and streaming parsed queries directly to the backend.</li>
    <li><strong>Adaptive Thresholding:</strong> Implement per-host dynamic thresholds that adjust sensitivity based on the client's baseline query volume.</li>
    <li><strong>DoH Handshake Metadata Analysis:</strong> Expand detection to Encrypted DNS by analyzing TLS packet sizes, inter-arrival times, and connection burst ratios.</li>
  </ol>

  <div class="card success" style="margin-top: 16px;">
  <strong>Final Conclusion & System Status:</strong><br>
  The CyberTrace DNS Exfiltration Detection system is <strong>FULLY FUNCTIONAL, VERIFIED, AND REPRODUCIBLE</strong>. The pipeline successfully bridges academic research and practical engineering: from synthetic data generation and leakage elimination to group-disjoint cross-validation, REST API serving, and an intuitive reactive dashboard.
  </div>
</div>

</body>
</html>
"""

html_content = (
    raw_html
    .replace("{{IMG_DASHBOARD}}", img_dashboard)
    .replace("{{IMG_BENIGN}}", img_benign)
    .replace("{{IMG_ATTACK}}", img_attack)
    .replace("{{IMG_BATCH}}", img_batch)
    .replace("{{IMG_BENCHMARKS}}", img_benchmarks)
    .replace("{{IMG_METRIC_CMP}}", img_metric_cmp)
    .replace("{{IMG_FPR_CMP}}", img_fpr_cmp)
    .replace("{{IMG_CM_RF}}", img_cm_rf)
)

OUTPUT_HTML.write_text(html_content, encoding="utf-8")
print(f"HTML written to {OUTPUT_HTML} ({len(html_content)} bytes)")

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
args = [
    edge_path,
    "--headless=new",
    "--disable-gpu",
    "--no-pdf-header-footer",
    f"--print-to-pdf={str(OUTPUT_PDF.resolve())}",
    str(OUTPUT_HTML.resolve()),
]

print("Compiling PDF with Microsoft Edge headless...")
res = subprocess.run(args, capture_output=True, text=True)

if res.returncode == 0 and OUTPUT_PDF.is_file():
    reader = pypdf.PdfReader(str(OUTPUT_PDF))
    page_count = len(reader.pages)
    print(f"SUCCESS: PDF created at {OUTPUT_PDF}")
    print(f"File size: {OUTPUT_PDF.stat().st_size} bytes")
    print(f"PAGE COUNT: {page_count} pages (Target: 12-15 pages)")
else:
    print(f"FAILED: {res.stderr}")
