# Spark Preprocessing Module

Contains PySpark ETL and feature transformation pipelines:
- `clean_logs.py`: Schema validation, type casting, filtering invalid records, timestamp parsing (`hour`, `day_of_week`), deduplication, and export to Parquet.
- `feature_engineering.py`: StringIndexer, OneHotEncoder, VectorAssembler, and scaling pipelines for PySpark MLlib.

## Execution
```bash
python spark/preprocessing/clean_logs.py
```
