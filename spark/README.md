# Apache Spark Module

Responsible for distributed in-memory log processing, cleaning, feature extraction, and threat analytics over millions of records.

## Responsibilities (Lead: Member 2)
- Phase 5: Spark Master & Worker cluster configuration
- Phase 6: Spark ETL pipeline (handling missing values, deduplication, schema normalization)
- Phase 7: Threat analytics (attack frequency, top attacking IPs, timeline distribution)
- Phase 10: Saving aggregated metrics back into MongoDB

## Directory Structure
- `jobs/`: General Spark jobs (e.g. connectivity tests, end-to-end batch runners).
- `preprocessing/`: PySpark ETL scripts (`clean_logs.py`, `feature_engineering.py`).
- `analytics/`: Aggregation scripts for threat intelligence (`attack_statistics.py`, `ip_analysis.py`, `timeline_analysis.py`).
