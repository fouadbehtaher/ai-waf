# Literature Review

## 1. Rule-based web application firewalls

Rule-based WAFs remain foundational because they provide deterministic protection against attack families that have stable textual signatures. OWASP Top 10 frames the most common application-layer risk families, while the OWASP Core Rule Set demonstrates how those risks are translated into reusable defensive rules [R1][R2].

Operational strengths of rule-based protection:

- deterministic decisions that are easy to explain to analysts
- strong precision against known signatures
- immediate blocking without training data

Operational weaknesses:

- limited adaptability against zero-day payloads and evasion
- maintenance burden as application traffic evolves
- weak generalization to suspicious behavior that does not match a known string pattern

This project therefore keeps a rule engine as the first defensive layer rather than treating machine learning as a full replacement.

## 2. Anomaly detection and machine learning in web security

Anomaly-oriented detection tries to identify behavior that deviates from normal request patterns instead of only matching a fixed signature. Isolation Forest is a suitable starting point because it isolates outliers efficiently and can work with benign-heavy data [R3][R4].

Why Isolation Forest is relevant here:

- it is lightweight enough for iterative retraining in a student project
- it can train on benign-heavy data
- it produces anomaly scores that can be combined with rule outputs

Its limitation is equally important: if the feature space or evaluation data do not represent realistic traffic diversity, the model can increase false positives without improving operational value. That outcome appears in the measured results of this project and becomes an explicit discussion point rather than something hidden.

## 3. Public datasets and reproducibility

Public datasets such as CICIDS2017 and CSIC 2010 remain useful in academic security projects because they provide labeled malicious and benign traffic for reproducible experimentation [R5][R6][R7]. However, they do not fully represent the deployment context of a specific application. For that reason, this project combines:

- normalized public data for repeatable evaluation
- locally captured and analyst-labeled traffic for deployment realism

This mixed strategy is academically stronger than relying on either source alone.

## 4. Why a hybrid WAF is the right framing

The literature and operational practice support a layered defense model:

- signatures and blacklists block high-confidence threats
- anomaly scoring highlights suspicious low-signal behavior
- rate limiting handles burst abuse and repeat offenders
- persistent telemetry supports retrospective analysis and retraining

This is the strongest fit for the project proposal because the goal is not only high detection, but also manageability, explainability, and real-time deployment viability.

## 5. Research gap addressed by this project

Many academic demonstrations stop at a notebook model or a single Flask route. The gap addressed here is broader:

- a real request pipeline with capture, scoring, and mitigation
- operational persistence through SQLite and PostgreSQL support
- distributed rate limiting via Redis-ready token buckets
- role-based analyst workflow and audit logging
- a React command center for review, blocking, labeling, deletion, and administration

That scope makes the project suitable not only as a coding exercise, but as a research prototype that can be evaluated across accuracy, latency, and governance dimensions.

## References

See [references.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/references.md).
