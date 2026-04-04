# Chapter 2: Literature Review

## 2.1 Rule-based application firewalls

Rule-based WAFs remain foundational because they provide deterministic protection against attack families that have stable textual signatures. OWASP guidance and the Core Rule Set illustrate how known risks such as SQL injection and XSS can be encoded into actionable blocking logic [R1][R2].

From an academic perspective, rule-based systems offer:

- strong interpretability
- high precision on known payload families
- immediate operational value without model training

However, they also have limits:

- they may miss evasion variants
- they may fail on novel malicious behavior
- they require maintenance as application traffic changes

This makes them necessary but not sufficient for an adaptive WAF.

## 2.2 Anomaly detection in web security

Machine learning can complement rules by detecting deviations from expected behavior rather than relying only on exact signatures. Among anomaly-oriented methods, Isolation Forest is attractive because it does not require a fully balanced supervised dataset and can be trained mostly on benign traffic [R3][R4].

In this project, Isolation Forest is chosen because:

- it fits a research prototype with limited labeled data
- it is computationally light enough for iterative experiments
- it produces a numerical anomaly score that can be combined with rule outputs

The project does not treat ML as a replacement for rules. Instead, ML is positioned as a second signal within a hybrid decision process.

## 2.3 Public datasets and reproducibility

Public datasets are important for repeatable security experiments. CICIDS2017 is widely used for intrusion and malicious-traffic research, and CSIC 2010 remains a classic source for web-request attack patterns [R5][R6][R7]. These datasets are useful because they let the experimenter repeat preprocessing, training, and evaluation under a documented workflow.

Still, public datasets have limits:

- they may not reflect the exact behavior of a deployed application
- they may overrepresent some attack types
- they may simplify real-world user behavior

Because of this, the project uses both public data and locally captured telemetry.

## 2.4 Hybrid WAFs in practice

The literature and operational practice support a layered approach:

- signatures and blacklists block high-confidence threats
- anomaly scoring highlights suspicious but previously unseen behavior
- telemetry storage supports retrospective analysis and retraining

This is the strongest fit for the project proposal because the goal is not only high detection, but also operational manageability and real-time deployment viability.

## 2.5 Research position of this project

This project sits between a pure academic prototype and a production engineering system. It does not stop at model training, and it does not stop at a rule list. Instead, it implements:

- a runnable gateway pipeline
- persistent storage
- label export and retraining
- role-based administration
- production-style deployment assets

That combination is what makes the project appropriate for an end-of-program proposal or capstone submission.

## 2.6 Literature-based design implications

The literature leads directly to the design choices adopted here:

- rules stay in the pipeline because explainability matters
- anomaly detection is added because rules alone cannot cover every suspicious pattern
- public data is normalized into the project schema for reproducibility
- local telemetry is retained for realism and iterative improvement
- benchmarks and false-positive analysis are necessary because detection quality alone is not enough

For the source list, see [references.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/references.md).
