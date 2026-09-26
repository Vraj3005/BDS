"""
Spark ETL Pipeline: Data Cleaning & Deduplication
Distributed Cyber Threat Intelligence Platform

Performs distributed data cleansing on raw network security logs:
1. Schema enforcement and type casting.
2. Filtering null, malformed, and negative flow metrics.
3. Timestamp parsing and temporal feature extraction (hour, day_of_week).
4. Attack label and protocol canonicalization.
5. Record deduplication.
6. Exports cleaned partition dataset to Parquet format.
"""

import os
import sys
import time
from pathlib import Path

# Ensure consistent python runtime across driver and workers
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, SPARK_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, trim, upper, to_timestamp, hour, dayofweek, when
)
from pyspark.sql.types import (
    StructType, StructField, StringType, LongType
)


def get_spark_session(app_name="CyberThreat-CleanLogs"):
    return (
        SparkSession.builder.appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def clean_network_logs(input_csv: Path = None, output_parquet: Path = None):
    input_path = input_csv or PATH_CONFIG["sample_csv"]
    output_path = output_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")

    if not input_path.exists():
        print(f"[-] Error: Input dataset not found at {input_path}")
        sys.exit(1)

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("           SPARK ETL PIPELINE: LOG CLEANSING")
    print("=" * 65)
    print(f"Source Dataset:       {input_path}")
    print(f"Target Output:        {output_path}")

    start_time = time.time()

    # 1. Read raw CSV
    print("\n[Step 1/5] Ingesting raw network security logs...")
    raw_df = spark.read.csv(str(input_path), header=True, inferSchema=True)
    raw_count = raw_df.count()
    print(f"  [OK] Ingested {raw_count:,} raw records with {len(raw_df.columns)} fields.")

    # 2. Schema Validation & Type Casting
    print("\n[Step 2/5] Casting fields to strong data types...")
    typed_df = (
        raw_df
        .withColumn("flow_duration", col("flow_duration").cast(LongType()))
        .withColumn("packet_length", col("packet_length").cast(LongType()))
        .withColumn("total_bytes", col("total_bytes").cast(LongType()))
        .withColumn("packet_count", col("packet_count").cast(LongType()))
        .withColumn("source_ip", trim(col("source_ip")))
        .withColumn("destination_ip", trim(col("destination_ip")))
        .withColumn("protocol", upper(trim(col("protocol"))))
        .withColumn("attack_type", trim(col("attack_type")))
        .withColumn("severity", trim(col("severity")))
    )

    # 3. Filtering Malformed & Corrupted Rows
    print("\n[Step 3/5] Filtering null IPs and invalid negative metrics...")
    valid_df = typed_df.filter(
        col("source_ip").isNotNull() & (col("source_ip") != "") &
        col("destination_ip").isNotNull() & (col("destination_ip") != "") &
        (col("flow_duration") >= 0) &
        (col("packet_length") >= 0) &
        (col("total_bytes") >= 0) &
        (col("packet_count") >= 0)
    )

    # 4. Parsing Timestamps & Extracting Temporal Features
    print("\n[Step 4/5] Parsing timestamps and deriving temporal features...")
    enriched_df = (
        valid_df
        .withColumn("parsed_timestamp", to_timestamp(col("timestamp"), "yyyy-MM-dd HH:mm:ss"))
        .withColumn("hour", hour(col("parsed_timestamp")))
        .withColumn("day_of_week", dayofweek(col("parsed_timestamp")))
        .drop("timestamp")
        .withColumnRenamed("parsed_timestamp", "timestamp")
    )

    # 5. Deduplication
    print("\n[Step 5/5] Deduplicating flow records...")
    cleaned_df = enriched_df.dropDuplicates([
        "timestamp", "source_ip", "destination_ip", "protocol", "flow_duration", "total_bytes"
    ])
    cleaned_count = cleaned_df.count()
    dropped_count = raw_count - cleaned_count

    # 6. Save to Parquet
    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting cleaned dataset to {output_path}...")
    cleaned_df.write.mode("overwrite").parquet(str(output_path))

    duration = time.time() - start_time

    print("=" * 65)
    print("                    CLEANSING SUMMARY")
    print("=" * 65)
    print(f"Total Raw Records:    {raw_count:,}")
    print(f"Cleaned Records:      {cleaned_count:,}")
    print(f"Dropped / Deduplicated: {dropped_count:,}")
    print(f"ETL Execution Time:   {duration:.2f}s")
    print("=" * 65)
    print("\nCleaned Schema:")
    cleaned_df.printSchema()

    spark.stop()
    return cleaned_df


if __name__ == "__main__":
    clean_network_logs()
