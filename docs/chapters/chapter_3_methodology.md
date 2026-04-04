# Chapter 3: Methodology and Design

## 3.1 Research methodology

The project follows a design-and-evaluate methodology:

1. implement the WAF pipeline end to end
2. normalize incoming requests into a structured schema
3. engineer behavioral and payload-oriented features
4. apply rules, anomaly scoring, and mitigation decisions
5. persist telemetry and support analyst labeling
6. train and evaluate a lightweight anomaly model
7. benchmark runtime performance and operational responses

## 3.2 Threat model

### In scope

- SQL injection
- cross-site scripting
- command injection
- path traversal
- suspicious payload correlation
- automated probing of sensitive paths
- burst abuse and repeat offenders
- targeted manual blocking and IP blacklisting

### Partially in scope

- credential stuffing
- rotating bot identities
- slow-rate abuse

### Out of scope

- volumetric L3/L4 DDoS
- kernel-level packet filtering
- enterprise TLS edge hardening
- malware delivery after successful application compromise

## 3.3 System design

The final architecture is described in [system_architecture.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/system_architecture.md). At runtime, the request path is:

1. receive the request from the client or edge proxy
2. apply token-bucket rate limiting
3. capture metadata and request body preview
4. extract numerical features
5. run deterministic rules
6. compute anomaly-aware score
7. decide allow, monitor, or block
8. optionally forward to the protected backend
9. store telemetry and expose it to the dashboard

## 3.4 Data strategy

The project uses two datasets:

- local labeled telemetry exported from the WAF itself
- a prepared public dataset aligned to the same schema

Generated dataset summary from [academic_results.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/academic_results.json):

| Dataset | Rows | Engineered feature columns | Label distribution |
|---|---:|---:|---|
| `labeled_requests.csv` | 14 | 28 | 7 malicious / 7 benign |
| `public_dataset_prepared.csv` | 14 | 30 | 7 malicious / 7 benign |

## 3.5 Feature engineering

The project extracts a mix of payload, protocol, and behavioral features, including:

- SQLi, XSS, traversal, and command-injection signals
- URL length and query length
- encoded character ratio
- body length and content type hints
- automated user-agent signal
- admin-path and login-path signal
- request-rate features per IP and per session
- token-bucket pressure
- fingerprint reuse and path novelty
- recent block ratio for repeat-offender behavior

This feature set is intentionally explainable. It supports both deterministic rules and anomaly scoring while remaining understandable to reviewers and analysts.

## 3.6 Model choice

The runtime pipeline is hybrid:

- rule engine for known attacks
- heuristic fallback for explainability and safe startup
- Isolation Forest for anomaly-oriented scoring

Isolation Forest was selected because:

- it is lightweight
- it does not require a large balanced supervised dataset
- it works naturally with anomaly scoring
- it fits a research prototype that may begin with limited labels

## 3.7 Baselines and evaluation plan

Three decision strategies are evaluated:

- rule-only: mark a request malicious when rule-derived attack types are present
- ML-only: mark a request malicious when the Isolation Forest score crosses the learned threshold
- hybrid: mark a request malicious if either rules or ML indicate maliciousness

Metrics:

- precision
- recall
- F1 score
- ROC-AUC
- false-positive rate
- average latency
- P50 latency
- P95 latency
- throughput

## 3.8 Experimental environments

Two runtime environments are part of the evaluation:

- local embedded mode:
  Flask app with embedded dashboard, SQLite, and storage-backed rate limiting
- production-style Docker mode:
  React SPA behind Nginx, Flask API behind Waitress, PostgreSQL, and Redis-backed rate limiting

Health evidence for both modes is available in:

- [health_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_local.json)
- [health_docker.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_docker.json)

## 3.9 Ethics and privacy

The project stores IP addresses and short payload previews, which creates privacy obligations. The implemented safeguards are:

- payload hashing for traceability
- short previews rather than unrestricted raw dumps
- analyst labeling rather than unrestricted data sharing
- documented export flow for research use
- explicit acknowledgement that IP addresses can be personal data

## 3.10 Reproducibility

The methodology is reproducible through:

- [train_model.py](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/scripts/train_model.py)
- [evaluate_model.py](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/scripts/evaluate_model.py)
- [benchmark_proxy.py](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/scripts/benchmark_proxy.py)
- [generate_academic_results.py](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/scripts/generate_academic_results.py)
- [appendices.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/appendices.md)
