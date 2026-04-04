# Chapter 5: Discussion and Conclusion

## 5.1 Discussion of findings

The project demonstrates that a complete WAF research prototype can be built around a hybrid design, but the measured outcomes also show that implementation completeness is not the same as model maturity.

The strongest result in this project is the overall system design:

- requests are truly intercepted and processed
- analysts can review, label, delete, block, and unblock
- the system supports both local research and production-style deployment
- every privileged action is tied to authentication and auditing

The most important research result is that the current rule engine outperforms the anomaly model on the available datasets. This is not a failure of the project. Instead, it is a meaningful result:

- the present datasets are small and highly separable by signatures
- the anomaly model has not yet seen enough representative benign traffic
- the hybrid pipeline increases false positives when the ML signal is not sufficiently calibrated

This is exactly the kind of finding that an academic report should state clearly.

## 5.2 Why the hybrid pipeline did not yet beat rules-only

Three reasons explain the result:

1. The current labeled datasets are small, balanced, and rule-friendly.
2. The malicious samples already contain strong signature indicators.
3. The anomaly model is being asked to generalize with limited diversity in normal traffic.

As a result, the rule layer already captures all positives, and the ML layer adds mostly extra false positives rather than extra useful recall.

## 5.3 Engineering strengths of the final system

Even though the model still needs refinement, the system now has substantial engineering value:

- separate API and SPA deployment modes
- PostgreSQL persistence and Redis-backed rate limiting
- Docker and Nginx deployment assets
- runtime configuration management
- role-based access control
- targeted block scopes instead of unsafe blanket blocking
- reproducible evaluation and benchmark scripts

These strengths make the project suitable for demonstration, grading, and future extension.

## 5.4 Limitations

The main limitations are:

- limited dataset size
- limited benign traffic diversity
- current Isolation Forest thresholding still produces high false-positive rates on prepared public data
- measured latency is higher than the original success target
- screenshots and polished visual reporting can still be expanded further if required for a final printed submission

## 5.5 Recommendations for future work

The next technical upgrades should be:

- collect a larger benign-heavy traffic corpus
- add a supervised baseline such as XGBoost or Logistic Regression for comparison
- separate anomaly scoring from blocking so ML can recommend monitoring before hard block
- add queue-backed logging and asynchronous persistence
- add observability, traces, and profiling to reduce latency
- integrate Redis for more benchmark scenarios and multi-instance tests
- add CI/CD and secrets management for stronger production hardening

## 5.6 Final conclusion

This project successfully evolved from a simple demo into a research-grade WAF prototype with:

- backend inspection and proxy logic
- a React command center
- real administrative actions
- PostgreSQL and Redis deployment support
- reproducible evaluation and benchmark artifacts
- a complete academic documentation package

The final conclusion is balanced:

- as an engineering prototype, the project is strong and coherent
- as an anomaly-detection study, it is promising but not yet optimized
- as an academic submission, it now provides both implementation depth and honest quantitative evidence
