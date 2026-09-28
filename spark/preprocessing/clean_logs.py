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
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, trim, upper, to_timestamp, hour, dayofweek
)
from pyspark.sql.types import LongType


def get_spark_session(app_name="CyberThreat-CleanLogs"):
    """Build and return a local SparkSession."""
    return (
        SparkSession.builder
        .appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )


def clean_network_logs(input_csv: Path = None, output_parquet: Path = None):
    """
    Run the full ETL cleaning pipeline.

    Args:
        input_csv:       Path to raw CSV file (defaults to PATH_CONFIG sample).
        output_parquet:  Destination Parquet path (defaults to processed dir).

    Returns:
        DataFrame of cleaned records.
    """
    input_path = input_csv or PATH_CONFIG["sample_csv"]
    output_path = output_parquet or (
        PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet"
    )

    if not Path(input_path).exists():
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

    # -------------------------------------------------------------------
    # Step 1: Read raw CSV
    # -------------------------------------------------------------------
    print("\n[Step 1/5] Ingesting raw network security logs...")
    raw_df = spark.read.csv(str(input_path), header=True, inferSchema=True)
    raw_count = raw_df.count()
    print(f"  [OK] Ingested {raw_count:,} raw records with {len(raw_df.columns)} fields.")

    # -------------------------------------------------------------------
    # Step 2: Type-cast numeric columns; trim/canonicalise strings
    # -------------------------------------------------------------------
    print("\n[Step 2/5] Casting fields to strong data types...")
    typed_df = (
        raw_df
        .withColumn("flow_duration",  col("flow_duration").cast(LongType()))
        .withColumn("packet_length",  col("packet_length").cast(LongType()))
        .withColumn("total_bytes",    col("total_bytes").cast(LongType()))
        .withColumn("packet_count",   col("packet_count").cast(LongType()))
        .withColumn("source_ip",      trim(col("source_ip")))
        .withColumn("destination_ip", trim(col("destination_ip")))
        .withColumn("protocol",       upper(trim(col("protocol"))))
        .withColumn("attack_type",    trim(col("attack_type")))
        .withColumn("severity",       trim(col("severity")))
    )
    print("  [OK] Type casting complete.")

    # -------------------------------------------------------------------
    # Step 3: Drop nulls and negative / impossible metric values
    # -------------------------------------------------------------------
    print("\n[Step 3/5] Filtering null IPs and invalid negative metrics...")
    valid_df = typed_df.filter(
        col("source_ip").isNotNull()      & (col("source_ip")      != "") &
        col("destination_ip").isNotNull() & (col("destination_ip") != "") &
        col("attack_type").isNotNull()    & (col("attack_type")    != "") &
        (col("flow_duration") >= 0) &
        (col("packet_length") >= 0) &
        (col("total_bytes")   >= 0) &
        (col("packet_count")  >= 0)
    )
    filtered_count = valid_df.count()
    print(f"  [OK] {filtered_count:,} valid records after null/negative filter "
          f"({raw_count - filtered_count:,} dropped).")

    # -------------------------------------------------------------------
    # Step 4: Parse timestamps -> temporal features
    # -------------------------------------------------------------------
    print("\n[Step 4/5] Parsing timestamps and deriving temporal features...")
    enriched_df = (
        valid_df
        .withColumn("parsed_ts",  to_timestamp(col("timestamp"), "yyyy-MM-dd HH:mm:ss"))
        .withColumn("hour",       hour(col("parsed_ts")))
        .withColumn("day_of_week", dayofweek(col("parsed_ts")))
        .drop("timestamp")
        .withColumnRenamed("parsed_ts", "timestamp")
    )
    print("  [OK] Temporal features (hour, day_of_week) derived.")

    # -------------------------------------------------------------------
    # Step 5: Deduplicate on natural flow key
    # -------------------------------------------------------------------
    print("\n[Step 5/5] Deduplicating flow records...")
    cleaned_df = enriched_df.dropDuplicates([
        "timestamp", "source_ip", "destination_ip",
        "protocol", "flow_duration", "total_bytes"
    ])
    cleaned_count = cleaned_df.count()
    dedup_dropped = filtered_count - cleaned_count
    print(f"  [OK] {cleaned_count:,} records after dedup ({dedup_dropped:,} duplicates removed).")

    # -------------------------------------------------------------------
    # Write Parquet output
    # -------------------------------------------------------------------
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting cleaned dataset -> {output_path} ...")
    cleaned_df.write.mode("overwrite").parquet(str(output_path))

    duration = time.time() - start_time

    print("=" * 65)
    print("                    CLEANSING SUMMARY")
    print("=" * 65)
    print(f"  Raw Records Ingested:      {raw_count:,}")
    print(f"  After Null/Neg Filter:     {filtered_count:,}")
    print(f"  After Deduplication:       {cleaned_count:,}")
    print(f"  Total Dropped:             {raw_count - cleaned_count:,}")
    print(f"  ETL Execution Time:        {duration:.2f}s")
    print(f"  Output Path:               {output_path}")
    print("=" * 65)
    cleaned_df.printSchema()

    spark.stop()
    return cleaned_count


if __name__ == "__main__":
    clean_network_logs()
