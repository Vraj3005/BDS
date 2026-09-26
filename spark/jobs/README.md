# Spark Jobs

Contains standalone driver jobs executable via `spark-submit` or Python:
- `test_connectivity.py`: Validates connection between Spark Driver and Master/Workers, runs parallelized distributed calculations, and verifies raw security log ingestion.
- `threat_analysis.py`: Main batch job executing full analytics pipeline across HDFS and MongoDB.
- `spark_to_mongodb.py`: Pipes analytics results directly into MongoDB collections.

## Execution
```bash
python spark/jobs/test_connectivity.py
# or via spark-submit
spark-submit spark/jobs/test_connectivity.py
```
