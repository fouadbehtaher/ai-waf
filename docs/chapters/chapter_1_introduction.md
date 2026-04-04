# Chapter 1: Introduction

## 1.1 Background

Web applications remain a major attack surface because they accept user-controlled input over HTTP and often expose sensitive data, authentication functions, and administrative workflows. Common attack families include SQL injection, cross-site scripting, command injection, path traversal, automated reconnaissance, and application-layer abuse bursts. These risks are reflected in the OWASP Top 10 and in modern operational guidance for application security [R1].

Traditional web application firewalls help by blocking known malicious patterns, but they are not sufficient on their own for every scenario. Static signatures can miss low-signal or novel abuse, while manual monitoring becomes increasingly difficult as traffic volume grows. This creates a clear need for a security layer that can combine explainable blocking logic with adaptive behavior.

## 1.2 Problem statement

The project addresses the following problem:

- web applications need real-time protection against malicious requests
- rules alone are not always enough for adaptive detection
- security decisions should remain explainable and manageable by analysts
- the system should support logging, labeling, retraining, and operational governance

## 1.3 Aim of the project

The aim is to design and evaluate an AI-based WAF that:

- intercepts incoming requests before they reach the protected backend
- extracts behavioral and payload-oriented features
- applies rule-based checks and anomaly-aware scoring
- decides whether to allow, monitor, or block the request
- stores telemetry for reporting, labeling, and retraining
- provides a dashboard for analyst review and administrative control

## 1.4 Research questions

The project is guided by the following questions:

1. Can a hybrid WAF that combines deterministic rules and anomaly-aware ML improve malicious request detection compared with rules alone?
2. Can the system maintain acceptable latency while inspecting requests in real time?
3. Which behavioral features are useful for distinguishing normal requests from abusive behavior?
4. Can persistent logging and analyst labeling support an iterative improvement loop?

## 1.5 Hypotheses

- H1: The hybrid pipeline will achieve higher recall than ML alone and will remain operationally practical.
- H2: The WAF can provide useful analyst control through targeted blocking, labeling, and audit logging.
- H3: A research prototype can be extended into a production-style architecture using PostgreSQL, Redis, Docker, and a separated frontend/backend design.

## 1.6 Objectives

To answer the research questions, the project sets the following objectives:

- implement a real inspection pipeline rather than a toy endpoint
- build a hybrid rule and anomaly-scoring workflow
- support both SQLite local mode and PostgreSQL production-style mode
- support both storage-backed and Redis-backed token buckets
- provide a React command center with roles: viewer, analyst, admin
- evaluate the system using labeled telemetry, prepared public data, and runtime benchmarks

## 1.7 Project contributions

The final system contributes the following:

- real request capture and reverse-proxy forwarding
- engineered request and behavioral features
- deterministic rule engine and anomaly-aware scoring
- targeted mitigation by signature, path, session, or IP
- role-based administration, sessions, and audit logging
- persistent telemetry export, retraining support, and academic evaluation artifacts

## 1.8 Scope

In scope:

- SQL injection, XSS, traversal, command injection
- rate limiting and repeat-offender handling
- analyst review, deletion, labeling, and targeted block workflows
- SQLite local research mode
- PostgreSQL and Redis production-style deployment support

Out of scope:

- volumetric L3/L4 DDoS mitigation
- enterprise SSO and centralized secrets management
- fully distributed multi-node tuning and observability stack

## 1.9 Report organization

- Chapter 2 reviews the literature and motivates a hybrid WAF design.
- Chapter 3 describes the methodology, datasets, threat model, and evaluation process.
- Chapter 4 presents the implementation and the measured results.
- Chapter 5 interprets the findings, limitations, and future work.

References: [references.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/references.md)
