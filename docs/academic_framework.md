# Academic Framework

## Research questions

1. Can a hybrid WAF that combines deterministic rules and anomaly-aware ML improve malicious request detection compared with rules alone?
2. Can the system maintain acceptable latency while inspecting requests in real time?
3. Which behavioral features contribute most to distinguishing benign traffic from web attacks?
4. Can logged traffic and analyst labeling support an iterative retraining loop for continuous improvement?

## Hypotheses

- H1: The hybrid pipeline will achieve higher recall than a rules-only baseline on previously unseen malicious requests.
- H2: The hybrid pipeline will reduce false negatives while keeping the false-positive rate within an acceptable operational range.
- H3: The gateway can inspect and forward requests with low enough overhead to remain practical for web applications.

## Success criteria

- Precision: at least 0.90 on the evaluation set.
- Recall: at least 0.85 on the evaluation set.
- F1 score: at least 0.87 on the evaluation set.
- False positive rate: below 0.05 on benign traffic.
- Average added latency: below 50 ms in local benchmark conditions.
- P95 latency: below 150 ms in local benchmark conditions.

## Threat model

### In scope

- SQL injection
- Cross-site scripting
- Path traversal
- Command injection
- Automated probing and reconnaissance
- Basic burst abuse and application-layer request floods
- Repeat offenders and suspicious session patterns

### Partially in scope

- Credential stuffing
- Slow-rate abuse
- Bot evasion through rotating identities

These can be approximated with rate limits and behavioral features, but need richer identity and distributed telemetry for stronger coverage.

### Out of scope

- Volumetric network DDoS at L3/L4
- TLS termination hardening
- Kernel-level packet filtering
- Browser exploit chains after successful payload delivery
- Full bot mitigation across globally distributed attackers

## Dataset strategy

### Public datasets

The project is designed to work with public intrusion and web-attack datasets such as:

- CSIC 2010 HTTP dataset for classic web-request attacks
- CICIDS2017 for broader intrusion behavior and malicious traffic families

To make these datasets usable by the project, `scripts/prepare_public_dataset.py` converts CSV or JSONL sources into the same normalized feature schema used by the local WAF telemetry export.

### Local dataset

The WAF also builds its own research dataset by:

1. capturing live requests
2. storing feature vectors and decisions
3. allowing analysts to assign labels
4. exporting labeled traffic as CSV for retraining

## Preprocessing methodology

1. Normalize all requests into a shared schema.
2. Keep method, path, query, session hints, content type, and selected client metadata.
3. Store payload hash and short preview instead of unrestricted raw payload dumps.
4. Extract engineered numerical features from content and short-term history.
5. Convert analyst labels into binary classes:
   benign = 0
   malicious = 1
6. Split the labeled dataset into train, validation, and test sets.
7. Train the anomaly model only on benign training samples when using Isolation Forest.

The repository therefore supports both:

- live labeled exports through `scripts/export_labeled_dataset.py`
- public dataset normalization through `scripts/prepare_public_dataset.py`

## Model choice and justification

The runtime design is hybrid:

- Rule engine: handles known high-confidence signatures such as SQLi, XSS, traversal, and blacklist hits.
- Weighted heuristic model: keeps the system explainable and operational even before a trained artifact exists.
- Isolation Forest: supports anomaly detection and is appropriate when malicious samples are relatively scarce or changing over time.

Isolation Forest is a practical fit because:

- it works well for anomaly-oriented detection
- it does not require fully balanced class distributions
- it can be trained on benign-heavy traffic
- it is lightweight enough for iterative retraining

## Class imbalance handling

The project addresses class imbalance in two ways:

1. anomaly modeling trains primarily on benign traffic
2. evaluation still uses labeled malicious samples to measure detection quality realistically

For future supervised baselines, class weighting or resampling can be added.

## Evaluation methodology

### Baselines

- Rule-only baseline
- ML-only anomaly baseline
- Hybrid rules + ML decision pipeline

### Metrics

- Precision
- Recall
- F1 score
- ROC-AUC
- False positive rate
- Average latency
- P50 latency
- P95 latency
- Throughput in requests per second

### Experimental flow

1. Collect and label traffic.
2. Export the labeled dataset.
3. Train the anomaly model on the training split.
4. Select a threshold on the validation split.
5. Evaluate final performance on the held-out test split.
6. Compare hybrid, rules-only, and ML-only metrics.
7. Run latency and throughput benchmarks against the proxy endpoint.

## Reporting

The project includes:

- dashboard for operational visibility
- summary report endpoint
- CSV event export
- dataset export for research experiments

## Limitations

- SQLite remains the default for research and local deployment, while PostgreSQL support is now available for production-style environments and still needs live infrastructure validation.
- Token-bucket rate limiting now supports Redis-backed distributed state, but clustered production tuning still needs operational benchmarking.
- The ML pipeline is ready for trained artifacts, but the final quality still depends on dataset quality and labeling discipline.

## Ethics and privacy

Because the system records IPs and payload previews, the project adopts the following research guardrails:

- minimize retained payload content
- store payload hashes for traceability
- support labeling without retaining full secrets whenever possible
- define retention windows for logs and datasets
- restrict exported datasets to approved research use
- document that IP addresses may be personal data under some regulations
