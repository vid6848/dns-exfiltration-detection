# DNS Exfiltration Detection Using Network Traffic Analysis

## Implemented Random Forest training

The latest workflow adds nested domain-group validation, balanced domain
coverage per fold, and conservative threshold selection under explicit
false-positive targets. Run `python -m src.ml.robust_train`; see the
[v0.2 validation workflow](docs/robust_random_forest.md). The original v0.1
experiment remains available below for reproducibility and comparison.

The [v0.2 results](artifacts/random_forest_v0.2/RESULTS.md) still show a 99.83%
false-positive rate when the AWS apex is entirely unseen. The model is a
development artifact, not ready for deployment. A separate public benign probe
had 6 false positives in 15,000 queries; see [public dataset research and probe
instructions](docs/public_benign_data_research.md). Broader cloud/CDN benign
coverage remains necessary.

The offline training stage now provides domain-disjoint train/validation/test
splits, the exact ten-feature input contract, validation-selected Random Forest
training, and a saved inference bundle with its feature order and decision
threshold. The statistical baseline is re-evaluated on the same splits.

See [training and inference handoff](docs/random_forest_training.md) for setup,
reproduction, leakage controls, and limitations. Committed model and experiment
outputs are in [artifacts/random_forest_v0.1](artifacts/random_forest_v0.1).

## Project Overview

**Project:** DNS Exfiltration Detection Using Network Traffic Analysis  
**Team:** CyberTrace  
**Course:** Cryptography and Network Security (CE305/CS305)

DNS is normally used for domain-name resolution, but attackers can abuse DNS as a covert channel to transfer information from a compromised system. In DNS exfiltration, data can be encoded into DNS subdomain labels and sent through repeated queries to an attacker-controlled domain.

This project builds a lightweight detection system that analyzes **observable DNS traffic characteristics** and identifies traffic that is likely to be benign or related to DNS-based data exfiltration.

The project does **not** attempt to recover real sensitive information. It focuses on detecting suspicious behavior from DNS traffic.

---

# 1. Research Question

> **Can observable DNS traffic characteristics such as query length, entropy, label structure, query frequency, unique subdomains, and temporal behavior be used with an efficient machine-learning model to reliably distinguish benign DNS traffic from simulated DNS exfiltration while keeping false positives low?**

The project will answer this question by comparing:

1. A simple statistical/threshold-based detection approach.
2. A supervised machine-learning approach, primarily using **Random Forest**.

The final system will report precision, recall, F1-score, confusion matrix, and false-positive rate.

---

# 2. Proposed Solution

The system will follow this pipeline:

```text
DNS Traffic / Dataset
        |
        v
Data Collection
        |
        v
Preprocessing
        |
        v
DNS Feature Extraction
        |
        +----------------------+
        |                      |
        v                      v
Statistical Baseline      ML Classifier
        |                 Random Forest
        |                      |
        +----------+-----------+
                   |
                   v
            Risk Classification
                   |
                   v
             Alert Generation
                   |
                   v
             Web Dashboard
```

The main idea is to avoid depending on a single suspicious characteristic. For example, a long DNS query by itself does not necessarily mean an attack. The system combines multiple features and uses a machine-learning model to make the final classification.

---

# 3. What We Will Build

The project will have five main parts:

### 3.1 DNS Traffic Collection

We will support:

- CSV/dataset-based DNS traffic for reliable experiments.
- Optional live DNS packet capture using Scapy.

For the main evaluation, labelled benign and simulated DNS-exfiltration traffic will be used.

Each record should contain information such as:

```text
timestamp
source_ip
destination_ip
domain/query
query_type
label
```

The `label` will identify the traffic as:

```text
0 = Benign
1 = Exfiltration
```

---

### 3.2 DNS Feature Extraction

The raw DNS query will be converted into numerical features that the ML model can understand.

Core features:

| Feature | Purpose |
|---|---|
| `query_length` | Measures total DNS query length |
| `longest_label_length` | Detects unusually long labels |
| `number_of_labels` | Measures domain structure |
| `entropy` | Detects random-looking/encoded labels |
| `digit_ratio` | Measures proportion of digits |
| `special_char_ratio` | Measures unusual character composition |
| `subdomain_length` | Measures size of the subdomain portion |
| `query_frequency` | Measures how frequently a domain is queried |
| `unique_subdomains` | Measures number of different subdomains |
| `time_interval` | Captures temporal query behavior |

The first version should use a **small, meaningful feature set** rather than hundreds of unnecessary features.

---

# 4. Feature Extraction Details

For every DNS query:

### Query Length

```text
query_length = length of complete domain/query
```

### Label Length

Split the domain into labels using `.` and find the longest label.

```text
abc123.example.com
```

The labels are:

```text
abc123
example
com
```

### Number of Labels

```text
number_of_labels = number of components separated by '.'
```

### Entropy

Calculate Shannon entropy of the relevant DNS label.

High entropy can indicate a random-looking or encoded string.

```text
H(X) = -Σ p(x) log2 p(x)
```

### Character Ratios

Calculate:

```text
digit_ratio
special_character_ratio
```

These help identify unusual subdomain composition.

### Query Frequency

Group queries by domain and calculate how many queries occur within a time window.

### Unique Subdomains

Count different subdomains associated with a domain during the observation period.

### Temporal Features

Measure the time between consecutive DNS queries and identify repeated/high-frequency patterns.

---

# 5. Statistical Baseline

Before using machine learning, we will create a simple statistical detector.

The baseline will identify suspicious traffic when multiple indicators cross experimentally determined thresholds.

Example:

```text
High query length
       +
High entropy
       +
High query frequency
       +
Many unique subdomains
       |
       v
Suspicious
```

The thresholds will be selected using the training/validation data rather than arbitrarily choosing values.

### Implemented baseline workflow

`src.baseline` implements this detector using four derived numerical inputs:
`query_length`, `entropy`, `query_frequency`, and `unique_subdomains`. A query
is suspicious when at least a configurable number of those values meet their
selected thresholds; automatic selection requires at least two corroborating
indicators. The raw `src_ip`, domain strings, and timestamps are used
only to construct the behavioral features and are never baseline inputs.

Threshold candidates are generated from the training partition only, then the
best rule is selected by validation F1-score (lower false-positive rate breaks
ties). For count features, a threshold of one is excluded because it represents
only the current query rather than repeated behavior. The held-out test
partition is evaluated only after selection. The evaluator uses a deterministic
stratified 60%/20%/20% train/validation/test split (seed 42). To run a read-only
evaluation on the cleaned project dataset:

```powershell
python -m src.baseline.evaluate_baseline --input data/processed/cleaned_unified_v0.1.csv
```

This baseline is important because the research question is not only:

> "Can ML detect DNS exfiltration?"

It is also:

> "Does the ML approach improve detection compared with a simple statistical method?"

---

# 6. Machine Learning Model

## Primary Model: Random Forest

The main classifier will be a **Random Forest Classifier**.

Reasons:

- Works well with structured/tabular data.
- Handles nonlinear relationships between DNS features.
- Does not require feature scaling for tree-based splits.
- Can work with a relatively small dataset.
- Provides feature importance.
- Fast enough for this project.
- Easier to explain than a deep-learning model.

The model will classify each traffic record as:

```text
Benign
or
Exfiltration
```

It will also provide a probability that can be converted into a risk score.

Example:

```text
Prediction: Exfiltration
Probability: 0.91
Risk Level: HIGH
```

---

# 7. Model Training Pipeline

```text
Raw DNS Dataset
       |
       v
Cleaning
       |
       v
Feature Extraction
       |
       v
Train / Validation / Test Split
       |
       v
Random Forest Training
       |
       v
Validation
       |
       v
Threshold / Model Selection
       |
       v
Final Test Evaluation
       |
       v
Save Model
```

The dataset will be split without mixing test information into training.

Where traffic is time-based, the project should prefer a time-aware split to reduce the chance of information leakage between training and testing.

---

# 8. Efficient Model Design

The goal is **not** to build the most complicated model.

The goal is to build a model that is:

- Accurate
- Fast
- Explainable
- Lightweight
- Suitable for real-time or near-real-time DNS analysis

We will start with:

```text
Random Forest
```

using a compact set of strong DNS features.

We can optionally compare it with:

```text
Logistic Regression
```

as a lightweight baseline model.

If Random Forest gives better F1-score and false-positive performance, it will be selected as the final model.

Deep learning will not be used unless experiments show a clear benefit, because the project primarily uses structured DNS traffic features.

---

# 9. Dataset

The project needs two traffic categories:

### Benign DNS Traffic

Examples:

```text
google.com
github.com
youtube.com
university websites
software update domains
normal application DNS requests
```

### Simulated DNS Exfiltration Traffic

We will generate **synthetic/simulated** DNS queries that imitate exfiltration-like characteristics.

For example:

```text
normal.example.com
```

versus simulated suspicious patterns such as:

```text
a8x92kdl29x8s7....example.com
```

The purpose is to create labelled traffic with observable characteristics associated with DNS tunneling/exfiltration, not to transmit real confidential information.

The final dataset should contain enough variation so that the model does not simply memorize one domain or one pattern.

---

# 10. Data Preprocessing

The preprocessing module will:

1. Load DNS data.
2. Remove invalid records.
3. Handle missing values.
4. Normalize domain/query fields.
5. Extract the required DNS labels.
6. Generate numerical features.
7. Remove duplicate/problematic records.
8. Create the final ML dataset.
9. Separate features `X` and target `y`.

Example:

```text
Raw DNS Record
      |
      v
Clean Record
      |
      v
Feature Extraction
      |
      v
Numerical Feature Vector
      |
      v
ML Dataset
```

---

# 11. Backend

## Technology

```text
Python
FastAPI
Pandas
NumPy
Scikit-learn
Scapy
Joblib
```

FastAPI will connect the trained model and analysis functions to the frontend.

### Main API endpoints

#### `POST /predict`

Accepts a DNS query or extracted feature data and returns:

```json
{
  "prediction": "Suspicious",
  "probability": 0.91,
  "risk_level": "HIGH"
}
```

#### `POST /analyze`

Analyzes an uploaded DNS dataset.

Returns:

```text
Total queries
Benign queries
Suspicious queries
Risk statistics
```

#### `GET /alerts`

Returns detected suspicious DNS activity.

#### `GET /statistics`

Returns traffic statistics for the dashboard.

#### `GET /model-performance`

Returns:

```text
Accuracy
Precision
Recall
F1-score
False Positive Rate
Confusion Matrix
```

---

# 12. Frontend

## Technology

```text
React.js
HTML
CSS
JavaScript
Recharts
```

The frontend will provide a simple cybersecurity dashboard.

### Dashboard Sections

```text
------------------------------------------------
DNS EXFILTRATION DETECTION
------------------------------------------------

Total DNS Queries       Suspicious       Benign
     12,540                238           12,302

------------------------------------------------
Traffic Analysis
[ Chart ]

------------------------------------------------
Suspicious DNS Activity

Domain          Risk       Probability
abc...com       HIGH          91%
x92...net       HIGH          87%

------------------------------------------------
Model Performance

Precision   Recall   F1 Score
  94%        92%       93%

------------------------------------------------
Feature Importance
[ Chart ]
------------------------------------------------
```

The dashboard should focus on useful information rather than adding unnecessary UI features.

---

# 13. Risk Classification

The ML prediction will be converted into an easy-to-understand risk level.

Example:

```text
Probability < 0.40
        LOW

0.40 - 0.70
        MEDIUM

> 0.70
        HIGH
```

These values are initial display thresholds and can be adjusted based on validation results.

The important output is the model's probability and classification, not the arbitrary label itself.

---

# 14. Alert System

When suspicious traffic is detected, the system will generate an alert.

Example:

```text
------------------------------------------
DNS SECURITY ALERT
------------------------------------------

Domain:
x92kd82.example.com

Prediction:
EXFILTRATION

Risk:
HIGH

Probability:
91%

Indicators:
- High entropy
- Long subdomain
- High query frequency
- Multiple unique subdomains

------------------------------------------
```

The alert explains **why** the traffic was considered suspicious using the extracted features.

---

# 15. Feature Importance

Random Forest allows us to identify which features contribute most to classification.

Example output:

```text
Feature                  Importance

entropy                    0.24
query_frequency            0.20
unique_subdomains          0.17
query_length               0.15
subdomain_length           0.10
digit_ratio                0.06
number_of_labels           0.05
time_interval              0.03
```

The actual values will come from our experiments.

This is important for the research component because we can answer:

> **Which DNS traffic characteristics are most useful for detecting simulated DNS exfiltration?**

---

# 16. Model Evaluation

The model will not be judged only by accuracy.

We will calculate:

### Accuracy

Overall percentage of correct predictions.

### Precision

Of the traffic predicted as exfiltration, how much was actually exfiltration?

### Recall

Of the actual exfiltration traffic, how much did the model detect?

### F1-score

Balance between precision and recall.

### False Positive Rate

How much legitimate DNS traffic was incorrectly flagged?

### Confusion Matrix

```text
                 Predicted
              Benign  Attack

Actual Benign    TN      FP
Actual Attack   FN      TP
```

The project will pay special attention to **false positives**, because legitimate DNS traffic can also contain long or random-looking domain names.

---

# 17. Experiments

We will perform the following experiments.

## Experiment 1 — Statistical Baseline

Evaluate the threshold-based detector.

Record:

```text
Precision
Recall
F1-score
False Positive Rate
```

## Experiment 2 — Random Forest

Train Random Forest on the same dataset.

Record the same metrics.

## Experiment 3 — Feature Analysis

Compare performance using:

```text
Basic features
+
Entropy
+
Frequency
+
Unique subdomains
+
Temporal features
```

This helps identify which feature groups improve detection.

## Experiment 4 — Model Efficiency

Measure:

```text
Training time
Prediction time
Model size
```

The final model should provide good detection without unnecessary computational complexity.

---

# 18. Expected Research Result

The final research conclusion should answer three things:

### 1. Can DNS traffic features detect exfiltration?

Determine whether the extracted DNS features allow the system to distinguish benign and simulated exfiltration traffic.

### 2. Does ML improve over simple thresholds?

Compare Random Forest with the statistical baseline using F1-score, recall, precision and false-positive rate.

### 3. Which features matter most?

Use Random Forest feature importance and experimental comparisons to identify the most useful DNS characteristics.

The project should not claim that the detector can identify every DNS exfiltration attack. The result should clearly state its performance on the selected dataset and simulated traffic.

---

# 19. Project Folder Structure

```text
dns-exfiltration-detection/
│
├── backend/
│   ├── main.py
│   ├── api/
│   │   ├── predict.py
│   │   ├── analysis.py
│   │   └── statistics.py
│   │
│   ├── detection/
│   │   ├── feature_extraction.py
│   │   ├── statistical_detector.py
│   │   └── predictor.py
│   │
│   ├── preprocessing/
│   │   └── preprocess.py
│   │
│   └── model/
│       ├── train.py
│       ├── evaluate.py
│       └── random_forest.joblib
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── README.md
│
├── notebooks/
│   ├── data_analysis.ipynb
│   ├── feature_analysis.ipynb
│   └── model_experiments.ipynb
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── App.jsx
│   └── package.json
│
├── capture/
│   └── dns_capture.py
│
├── tests/
│   ├── test_features.py
│   ├── test_detector.py
│   └── test_api.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

# 20. Important Functions

The main Python functions will be:

```python
capture_dns_traffic()
```

Captures/reads DNS traffic.

```python
preprocess_dns_data()
```

Cleans and prepares DNS records.

```python
extract_features()
```

Converts DNS queries into numerical features.

```python
calculate_entropy()
```

Calculates DNS-label entropy.

```python
calculate_query_frequency()
```

Calculates query frequency over time.

```python
calculate_unique_subdomains()
```

Calculates domain/subdomain diversity.

```python
statistical_detection()
```

Runs the threshold-based baseline.

```python
train_model()
```

Trains the Random Forest classifier.

```python
predict_dns()
```

Classifies new DNS traffic.

```python
generate_alert()
```

Creates an alert for suspicious traffic.

```python
evaluate_model()
```

Calculates evaluation metrics.

```python
get_feature_importance()
```

Identifies important DNS features.

---

# 21. Development Order

We will build the project in this order:

### Phase 1 — Dataset

- Collect/prepare benign DNS traffic.
- Generate/obtain labelled simulated exfiltration traffic.
- Create the initial CSV dataset.

### Phase 2 — Feature Engineering

- Implement domain parsing.
- Implement entropy.
- Implement length features.
- Implement frequency features.
- Implement unique-subdomain features.
- Implement temporal features.

### Phase 3 — Baseline

- Build the statistical detector.
- Test it.
- Record its metrics.

### Phase 4 — Machine Learning

- Split the dataset.
- Train Random Forest.
- Tune only the important parameters.
- Evaluate on unseen test data.
- Save the final model.

### Phase 5 — Backend

- Create FastAPI application.
- Add prediction endpoint.
- Add dataset analysis endpoint.
- Add statistics endpoint.
- Add alert endpoint.

### Phase 6 — Frontend

- Create React dashboard.
- Display traffic statistics.
- Display suspicious queries.
- Display risk levels.
- Display model metrics.
- Display feature importance.

### Phase 7 — Testing & Research

- Test with unseen traffic.
- Compare baseline vs Random Forest.
- Analyze false positives.
- Analyze important features.
- Measure prediction time.

### Phase 8 — Final Demonstration

```text
Upload/collect DNS traffic
        ↓
Analyze
        ↓
Extract features
        ↓
Run model
        ↓
Display prediction
        ↓
Show risk + reason
        ↓
Show overall statistics
```

---

# 22. Technology Stack Summary

| Layer | Technology |
|---|---|
| Programming | Python |
| Data Processing | Pandas, NumPy |
| Network Traffic | Scapy |
| Machine Learning | Scikit-learn |
| Main Model | Random Forest |
| Model Storage | Joblib |
| Backend | FastAPI |
| Frontend | React.js |
| Charts | Recharts |
| Database | SQLite (optional) |
| Development | VS Code / Jupyter / Colab |
| Version Control | Git + GitHub |

---

# 23. Project Scope

### Included

- DNS traffic analysis
- Benign vs simulated exfiltration classification
- DNS feature extraction
- Statistical detection baseline
- Random Forest ML classifier
- Risk classification
- Suspicious traffic alerts
- Dashboard
- Model evaluation
- Feature importance
- False-positive analysis

### Not Included in the Core Version

- Recovering real stolen data
- Deploying malware
- Attacking real systems
- Blocking all DNS traffic
- Full DNS-over-HTTPS inspection

DNS-over-HTTPS can be discussed as future work because encryption reduces visibility into the DNS query content required by the current feature-based approach.

---

# 24. Final Expected Output

At the end of the project, we will have a working prototype that can:

```text
                 ┌────────────────────┐
                 │    DNS Traffic     │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Feature Extraction │
                 └─────────┬──────────┘
                           ↓
              ┌────────────┴────────────┐
              ↓                         ↓
      Statistical Model          Random Forest
              ↓                         ↓
              └────────────┬────────────┘
                           ↓
                   Risk Classification
                           ↓
                  ┌─────────────────┐
                  │   Dashboard     │
                  └─────────────────┘
```

The final research output will show:

- How effectively DNS traffic features identify simulated exfiltration.
- Whether Random Forest performs better than the statistical baseline.
- Which DNS features contribute most to detection.
- How many false positives the system produces.
- Whether the model is lightweight enough for practical DNS traffic analysis.

---

# 25. Final Goal

The final system should be a **simple, efficient and explainable DNS exfiltration detection prototype**, rather than an unnecessarily complex cybersecurity platform.

The core contribution is:

> **Combining interpretable DNS traffic features, a statistical baseline, and an efficient Random Forest classifier to detect suspicious DNS exfiltration patterns while explicitly evaluating false positives.**
