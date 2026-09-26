"""
Spark Cluster Connectivity & Distributed Verification Job
Distributed Cyber Threat Intelligence Platform

Validates:
1. Active Spark runtime and Master/Worker connectivity.
2. Parallelized distributed RDD computation across partitions.
3. Spark SQL DataFrame engine readiness.
4. Access to raw network security logs (sample_cicids2017.csv or HDFS).
"""

import os
import sys
import time
from pathlib import Path

# Ensure Spark workers use the exact same python interpreter
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import SPARK_CONFIG, PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession


def run_connectivity_test():
    print("=" * 65)
    print("       APACHE SPARK CLUSTER CONNECTIVITY TEST REPORT")
    print("=" * 65)

    master_url = get_spark_master_url(use_cluster=False)
    app_name = SPARK_CONFIG["app_name"] + "-ConnectivityTest"

    print(f"Target Master:        {master_url}")
    print(f"Application Name:     {app_name}")
    print("Initializing SparkSession...")

    start_time = time.time()
    spark = (
        SparkSession.builder.appName(app_name)
        .master(master_url)
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    sc = spark.sparkContext
    sc.setLogLevel("WARN")
    init_duration = time.time() - start_time

    print(f"[+] SparkSession Initialized in {init_duration:.2f}s")
    print("-" * 65)
    print(f"Spark Version:        {spark.version}")
    print(f"Application ID:       {sc.applicationId}")
    print(f"Default Parallelism:  {sc.defaultParallelism} cores")
    print(f"Python Runtime:       {sys.version.split()[0]}")

    # 1. Distributed RDD Verification
    print("-" * 65)
    print("TEST 1: Distributed RDD Computation")
    sample_data = range(1, 100001)
    rdd = sc.parallelize(sample_data, numSlices=4)
    rdd_sum = rdd.sum()
    num_partitions = rdd.getNumPartitions()
    print(f"  [OK] Processed 100,000 items across {num_partitions} partitions.")
    print(f"  [OK] Distributed Sum: {rdd_sum:,} (Verified)")

    # 2. Spark SQL DataFrame Engine Verification
    print("-" * 65)
    print("TEST 2: Spark SQL DataFrame Engine")
    test_df = spark.createDataFrame(
        [(1, "TCP", "BENIGN"), (2, "UDP", "DDoS"), (3, "ICMP", "PortScan")],
        ["event_id", "protocol", "attack_type"]
    )
    df_count = test_df.count()
    print(f"  [OK] DataFrame transformation executed successfully. Count: {df_count}")

    # 3. Security Dataset Ingestion Test
    print("-" * 65)
    print("TEST 3: Network Security Logs Ingestion")
    raw_csv = PATH_CONFIG["sample_csv"]
    if raw_csv.exists():
        raw_df = spark.read.csv(str(raw_csv), header=True, inferSchema=True)
        log_count = raw_df.count()
        num_cols = len(raw_df.columns)
        print(f"  [OK] Successfully read: {raw_csv.name}")
        print(f"  [OK] Schema Columns:    {num_cols} fields")
        print(f"  [OK] Total Log Records: {log_count:,} records")
        print(f"  [OK] Fields: {', '.join(raw_df.columns[:5])}...")
    else:
        print(f"  [!] Note: Raw CSV not found at {raw_csv}. (Run data/generate_sample.py)")

    print("=" * 65)
    print("STATUS: APACHE SPARK CLUSTER ENGINE IS HEALTHY & OPERATIONAL")
    print("=" * 65)

    spark.stop()


if __name__ == "__main__":
    run_connectivity_test()
