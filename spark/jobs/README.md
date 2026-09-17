# Spark Jobs

Contains standalone driver jobs executable via `spark-submit`:
- `test_connectivity.py`: Validates connection between Spark Driver and Master/Workers.
- `spark_to_mongodb.py`: Pipes analytics results directly into MongoDB collections.
- `threat_analysis.py`: Main batch job executing full analytics pipeline.
