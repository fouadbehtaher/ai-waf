# Academic Results Summary

## Dataset summary

| Dataset | Rows | Feature columns | Label distribution |
|---|---:|---:|---|
| labeled_requests.csv | 14 | 28 | {"malicious": 7, "benign": 7} |
| public_dataset_prepared.csv | 14 | 30 | {"malicious": 7, "benign": 7} |

## Labeled telemetry evaluation

Model version: `iforest-live-check`

| Pipeline | Precision | Recall | F1 | ROC-AUC | FPR | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rule only | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 7 | 0 | 7 | 0 |
| ml only | 0.6667 | 0.8571 | 0.7500 | 0.7959 | 0.4286 | 6 | 3 | 4 | 1 |
| hybrid | 0.7000 | 1.0000 | 0.8235 | 1.0000 | 0.4286 | 7 | 3 | 4 | 0 |

## Prepared public dataset evaluation

Model version: `iforest-live-check`

| Pipeline | Precision | Recall | F1 | ROC-AUC | FPR | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rule only | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 7 | 0 | 7 | 0 |
| ml only | 0.5000 | 1.0000 | 0.6667 | 0.4694 | 1.0000 | 7 | 7 | 0 | 0 |
| hybrid | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 1.0000 | 7 | 7 | 0 | 0 |

## Benchmarks

| Scenario | Avg latency ms | P50 latency ms | P95 latency ms | Throughput rps | Requests | Concurrency |
|---|---:|---:|---:|---:|---:|---:|
| Local proxy | 244.4988 | 234.7051 | 365.3692 | 15.2872 | 20 | 4 |
| Docker proxy | 168.9584 | 159.6205 | 206.9271 | 22.8297 | 20 | 4 |
| Local inspect | 461.2160 | 458.5142 | 560.4700 | 8.1188 | 20 | 4 |
| Docker inspect | 203.4430 | 201.3700 | 259.0585 | 18.8236 | 20 | 4 |

## Rate-limit stress evidence

- URL: `http://127.0.0.1:8081/inspect?message=stress-check`
- Requests: `80` at concurrency `16`
- Status counts: `{"200": 43, "403": 37}`

## Test evidence

- Status: `ok`
- Tests run: `9`
- Duration seconds: `10.604`
