# Chapter 4: Implementation and Results

## 4.1 Implementation overview

The implemented system contains the following major parts:

- Flask WAF API for capture, inspection, forwarding, and administration
- React SPA command center for reviewing requests and applying actions
- SQLite local persistence and PostgreSQL production-style persistence
- storage-backed and Redis-backed token-bucket rate limiting
- role-based access control with viewer, analyst, and admin roles
- audit logging for privileged actions
- scripts for export, training, evaluation, benchmarking, and migration

## 4.2 Backend implementation

The backend handles:

- request capture and normalization
- feature extraction from payloads and behavior
- rule evaluation
- anomaly score generation
- mitigation decisions
- proxy forwarding to the protected backend
- request persistence and later retrieval

The API also supports:

- authentication and bearer tokens
- blacklist management
- targeted manual block rules
- request labeling
- request deletion
- runtime settings changes
- user management and audit review

## 4.3 Frontend implementation

The React command center provides:

- login flow
- request table and detail view
- targeted block actions by signature, path, session, or IP
- blacklist management
- request labeling and deletion
- runtime settings editing
- user and audit management for admins

This elevates the project beyond a notebook or single Flask demo and gives it an actual control plane.

## 4.4 Deployment implementation

Two validated deployment paths are now included:

- local embedded mode:
  Flask + embedded dashboard + SQLite + storage token bucket
- production-style Docker mode:
  Nginx + React SPA + Flask API + PostgreSQL + Redis + sample backend

The Docker stack was verified live on this machine with the following working paths:

- `http://127.0.0.1:8081/dashboard/`
- `http://127.0.0.1:8081/health`
- `http://127.0.0.1:8081/api/auth/login`
- `http://127.0.0.1:8081/proxy/api/hello?name=prod`

## 4.5 Detection results on labeled telemetry

Results generated in [academic_results.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/academic_results.json):

| Pipeline | Precision | Recall | F1 | ROC-AUC | FPR | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rule-only | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 7 | 0 | 7 | 0 |
| ML-only | 0.6667 | 0.8571 | 0.7500 | 0.7959 | 0.4286 | 6 | 3 | 4 | 1 |
| Hybrid | 0.7000 | 1.0000 | 0.8235 | 1.0000 | 0.4286 | 7 | 3 | 4 | 0 |

Interpretation:

- the rules already separate the current labeled telemetry perfectly
- the ML model improves recall relative to itself, but introduces false positives
- the hybrid pipeline does not improve over rules-only on this small dataset because the rule layer already captures all positives

## 4.6 Results on prepared public dataset

| Pipeline | Precision | Recall | F1 | ROC-AUC | FPR | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rule-only | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 7 | 0 | 7 | 0 |
| ML-only | 0.5000 | 1.0000 | 0.6667 | 0.4694 | 1.0000 | 7 | 7 | 0 | 0 |
| Hybrid | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 1.0000 | 7 | 7 | 0 | 0 |

Interpretation:

- the prepared public sample is still best handled by the rule engine
- the current anomaly artifact does not generalize well to this prepared public sample
- this validates the need for better data volume, broader benign traffic, and better threshold tuning

## 4.7 Runtime benchmark results

### Proxy end-to-end benchmark

| Environment | Avg latency ms | P50 latency ms | P95 latency ms | Throughput rps | Requests | Concurrency |
|---|---:|---:|---:|---:|---:|---:|
| Local proxy | 244.4988 | 234.7051 | 365.3692 | 15.2872 | 20 | 4 |
| Docker proxy | 168.9584 | 159.6205 | 206.9271 | 22.8297 | 20 | 4 |

### Inspection-only benchmark

| Environment | Avg latency ms | P50 latency ms | P95 latency ms | Throughput rps | Requests | Concurrency |
|---|---:|---:|---:|---:|---:|---:|
| Local inspect | 461.2160 | 458.5142 | 560.4700 | 8.1188 | 20 | 4 |
| Docker inspect | 203.4430 | 201.3700 | 259.0585 | 18.8236 | 20 | 4 |

These measurements are honest local workstation numbers rather than idealized targets. They show the system is functional, but they also show that more performance optimization is still needed to satisfy the original latency ambition.

## 4.8 Stress evidence for adaptive blocking

The stress evidence file [rate_limit_stress.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/rate_limit_stress.json) recorded:

- 80 requests at concurrency 16
- 43 responses with status `200`
- 37 responses with status `403`

This demonstrates that the runtime protection layer actively enforces rate-based defensive decisions under higher load.

## 4.9 Operational evidence

Automated verification succeeded:

- 9 automated tests passed in 10.604 seconds according to [test_results.txt](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/test_results.txt)
- the Docker health snapshot confirms PostgreSQL and Redis mode in [health_docker.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_docker.json)
- the local health snapshot confirms SQLite and storage-backed rate limiting in [health_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_local.json)

## 4.10 Assessment against success criteria

| Criterion | Target | Observed status |
|---|---|---|
| Precision | >= 0.90 | Achieved by rule-only, not by ML-only or hybrid on the public sample |
| Recall | >= 0.85 | Achieved across the current labeled experiments |
| F1 score | >= 0.87 | Achieved only by rule-only on the current datasets |
| False positive rate | < 0.05 | Achieved by rule-only, not by ML-only or hybrid |
| Average added latency | < 50 ms | Not achieved in current local and Docker measurements |
| P95 latency | < 150 ms | Not achieved in current local and Docker measurements |

## 4.11 Result summary

The implementation goals were achieved: the project now works as a full WAF research prototype with administration, persistence, deployment assets, and evaluation artifacts. The research results are mixed but useful:

- implementation maturity is strong
- rule-based accuracy on the current datasets is strong
- anomaly performance still needs improvement
- latency optimization remains future work
