# Presentation Deck

## Slide 1: Title

- AI-Based Web Application Firewall
- Hybrid rules, anomaly scoring, targeted mitigation, and analyst control
- Capstone / final-year security project

Speaker note:
Introduce the project as a full security gateway rather than a single model or a toy Flask route.

## Slide 2: Problem

- Web applications remain exposed to SQLi, XSS, traversal, probing, and abuse bursts
- Rule-only protection is useful but limited against adaptive behavior
- Manual monitoring does not scale well

Speaker note:
Frame the problem around both security accuracy and operational manageability.

## Slide 3: Objectives

- Inspect requests in real time
- Combine explainable rules with anomaly-aware scoring
- Persist telemetry for analysis and retraining
- Give analysts real control over block, review, and deletion workflows

## Slide 4: System architecture

Use [system_architecture.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/system_architecture.md).

Speaker note:
Walk through edge, API, rules, features, scoring, mitigation, backend, database, Redis, and control plane.

## Slide 5: Detection pipeline

1. Capture request
2. Extract features
3. Check deterministic rules
4. Compute anomaly score
5. Decide allow, monitor, or block
6. Log telemetry and expose to dashboard

## Slide 6: Frontend and admin workflow

- React SPA command center
- Viewer, analyst, and admin roles
- Targeted block by signature, path, session, or IP
- Blacklist management, labeling, deletion, audit trail

## Slide 7: Data and model

- Local labeled telemetry: 14 rows, 28 engineered features
- Prepared public dataset: 14 rows, 30 engineered features
- Active anomaly model: `iforest-live-check`
- Baselines: rules-only, ML-only, hybrid

## Slide 8: Accuracy results

Labeled telemetry:

- Rule-only F1: `1.0000`
- ML-only F1: `0.7500`
- Hybrid F1: `0.8235`

Prepared public dataset:

- Rule-only F1: `1.0000`
- ML-only F1: `0.6667`
- Hybrid F1: `0.6667`

Speaker note:
Explain honestly that the current anomaly model does not yet beat the rules-only baseline on the current datasets.

## Slide 9: Runtime results

Proxy benchmark:

- Local: `244.50 ms` average, `15.29 rps`
- Docker: `168.96 ms` average, `22.83 rps`

Inspection benchmark:

- Local: `461.22 ms` average
- Docker: `203.44 ms` average

Stress result:

- `80` requests at concurrency `16`
- `43` allowed, `37` blocked

## Slide 10: Production-readiness upgrades completed

- Flask API / React SPA separation
- PostgreSQL-ready persistence
- Redis-backed distributed token bucket
- Docker Compose and Nginx deployment
- Auth, roles, sessions, audit logging

## Slide 11: Limitations

- Current datasets are small
- Isolation Forest still raises false positives
- Latency target of sub-50 ms was not achieved in current measurements
- More benign traffic diversity is needed

## Slide 12: Future work

- Larger and more realistic traffic corpus
- Supervised baseline such as XGBoost
- Better ML calibration and thresholding
- Observability and profiling for latency reduction
- CI/CD and secrets management

## Slide 13: Conclusion

- The project is now a coherent WAF research prototype
- Engineering scope is strong and demonstrable
- Academic results are honest: rules currently dominate, ML still needs improvement
- The system is ready for submission, demo, and next-stage refinement
