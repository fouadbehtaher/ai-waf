# Final Report Package

This repository now contains a full academic delivery package for the AI-Based Web Application Firewall project.

## Abstract

This project implements a hybrid web application firewall that combines deterministic rules, behavioral feature extraction, anomaly-aware scoring, targeted mitigation, persistent storage, and an analyst-facing React command center. The system supports both a local embedded mode and a production-style separated deployment using Flask, React, PostgreSQL, Redis, Docker, and Nginx. Experimental results show that the rule engine is highly effective on the current labeled datasets, while the Isolation Forest anomaly model still introduces false positives and therefore does not yet outperform the rules-only baseline. The project nevertheless demonstrates a complete research workflow: request capture, storage, labeling, export, training, evaluation, benchmark measurement, administration, and deployment.

## Chapters

1. [Chapter 1: Introduction](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/chapter_1_introduction.md)
2. [Chapter 2: Literature Review](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/chapter_2_literature_review.md)
3. [Chapter 3: Methodology and Design](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/chapter_3_methodology.md)
4. [Chapter 4: Implementation and Results](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/chapter_4_implementation_results.md)
5. [Chapter 5: Discussion and Conclusion](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/chapter_5_discussion_conclusion.md)
6. [Appendices](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/appendices.md)

## Key generated evidence

- Academic metrics summary: [academic_results.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/academic_results.md)
- Machine-readable metrics: [academic_results.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/academic_results.json)
- Local benchmark: [benchmark_summary_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_summary_local.json)
- Docker benchmark: [benchmark_summary.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_summary.json)
- Inspection benchmark local: [benchmark_inspect_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_inspect_local.json)
- Inspection benchmark docker: [benchmark_inspect_docker.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_inspect_docker.json)
- Rate-limit stress evidence: [rate_limit_stress.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/rate_limit_stress.json)
- Automated tests evidence: [test_results.txt](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/test_results.txt)
- Health snapshots: [health_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_local.json) and [health_docker.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_docker.json)

## Architecture and presentation assets

- Architecture diagrams: [system_architecture.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/system_architecture.md)
- Presentation deck: [presentation_deck.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/presentation_deck.md)
- References: [references.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/references.md)

## Reproducibility

To regenerate the academic metrics package:

```powershell
cd C:\Users\tamat\OneDrive\Desktop\wafai\waf_project
python scripts\generate_academic_results.py
```

To regenerate tests and benchmarks, follow the workflow in [appendices.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/docs/chapters/appendices.md).
