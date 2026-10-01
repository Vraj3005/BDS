"""
Threat Intelligence & IP Risk Scoring Engine
Distributed Cyber Threat Intelligence Platform

Calculates composite 0-100 IP Risk Scores and Threat Reputation:
1. Aggregates multi-dimensional threat signals per source IP:
   - Attack frequency and flow ratio
   - Attack severity multiplier
   - Target destination dispersion (blast radius)
2. Computes composite 0-100 Risk Score.
3. Categorizes IPs into Low, Medium, High, and Critical risk tiers.
4. Exports risk scoring records to Parquet and MongoDB 'ip_reputation'.
5. Supports interactive CLI lookup for incident responders.
"""

import os
import sys
import argparse
import time
from datetime import datetime
from pathlib import Path

# Ensure worker processes use sys.executable
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, MONGO_CONFIG, get_spark_master_url, get_mongo_client
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, count, countDistinct, avg, max as spark_max, when, round as spark_round, lit
)


def get_spark_session(app_name="CyberThreat-RiskEngine"):
    return (
        SparkSession.builder.appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def compute_ip_risk_scores(input_parquet: Path = None, output_parquet: Path = None, write_mongo: bool = False):
    in_path = input_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")
    out_path = output_parquet or (PATH_CONFIG["processed_data_dir"] / "ip_risk_scores.parquet")

    if not in_path.exists():
        print(f"[-] Input data not found at {in_path}. Running clean_logs.py...")
        from spark.preprocessing.clean_logs import clean_network_logs
        clean_network_logs()

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("      THREAT INTELLIGENCE & IP RISK SCORING ENGINE")
    print("=" * 65)
    print(f"Source Dataset:       {in_path}")
    print(f"Target Output:        {out_path}")

    start_time = time.time()

    # 1. Load cleaned network logs
    print("\n[Step 1/4] Ingesting cleaned logs...")
    df = spark.read.parquet(str(in_path))
    total_logs = df.count()
    print(f"  [OK] Ingested {total_logs:,} network flow records.")

    # 2. Derive Numeric Severity Weight
    weighted_df = df.withColumn(
        "severity_weight",
        when(col("attack_type") == "DDoS", 40)
        .when(col("attack_type") == "Botnet", 30)
        .when(col("attack_type") == "BruteForce", 25)
        .when(col("attack_type") == "PortScan", 15)
        .otherwise(0)
    ).withColumn(
        "is_attack",
        when(col("attack_type") != "BENIGN", 1).otherwise(0)
    )

    # 3. Aggregate Threat Metrics per Source IP
    print("\n[Step 2/4] Aggregating threat signals per source IP...")
    ip_stats = weighted_df.groupBy("source_ip").agg(
        count("source_ip").alias("total_flows"),
        count(when(col("is_attack") == 1, True)).alias("attack_count"),
        countDistinct("destination_ip").alias("unique_destinations"),
        countDistinct("attack_type").alias("unique_attack_types"),
        spark_max("severity_weight").alias("max_severity_weight"),
        spark_round(avg("total_bytes"), 2).alias("avg_bytes_per_flow")
    )

    # 4. Calculate 0 - 100 Composite Risk Score
    print("\n[Step 3/4] Calculating composite 0-100 Risk Score formula...")
    # Formula components:
    # 1. Attack Frequency (up to 40 pts)
    # 2. Attack Severity Weight (up to 40 pts)
    # 3. Target Dispersion (up to 20 pts)
    scored_df = ip_stats.withColumn(
        "frequency_score",
        when(col("attack_count") >= 10, 40)
        .otherwise(col("attack_count") * 4)
    ).withColumn(
        "dispersion_score",
        when(col("unique_destinations") >= 5, 20)
        .otherwise(col("unique_destinations") * 4)
    ).withColumn(
        "raw_risk_score",
        col("frequency_score") + col("max_severity_weight") + col("dispersion_score")
    ).withColumn(
        "risk_score",
        when(col("attack_count") == 0, 10)  # Clean benign traffic baseline
        .when(col("raw_risk_score") > 100, 100)
        .otherwise(col("raw_risk_score"))
    ).withColumn(
        "risk_level",
        when(col("risk_score") >= 76, "Critical")
        .when(col("risk_score") >= 51, "High")
        .when(col("risk_score") >= 26, "Medium")
        .otherwise("Low")
    ).withColumn(
        "recommended_action",
        when(col("risk_level") == "Critical", "Auto-Block & Quarantine")
        .when(col("risk_level") == "High", "Active Firewall Throttle")
        .when(col("risk_level") == "Medium", "Rate-limit & Deep Inspection")
        .otherwise("Standard Network Monitoring")
    ).select(
        "source_ip", "total_flows", "attack_count", "unique_destinations",
        "risk_score", "risk_level", "recommended_action"
    ).orderBy(col("risk_score").desc(), col("attack_count").desc())

    scored_count = scored_df.count()

    # 5. Export to Parquet
    print(f"\n[Step 4/4] Writing scored IP intelligence to {out_path}...")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    scored_df.write.mode("overwrite").parquet(str(out_path))

    # Display Top High Risk Threat Actors
    print("\n" + "=" * 65)
    print("               TOP HIGH-RISK THREAT ACTORS")
    print("=" * 65)
    scored_df.show(10, truncate=False)

    # Optional MongoDB export
    if write_mongo:
        try:
            print("\nExporting IP reputation profile to MongoDB Atlas...")
            client = get_mongo_client()
            db = client[MONGO_CONFIG["db_name"]]
            col_name = MONGO_CONFIG["collections"]["ip_reputation"]

            # Convert top records to dict
            top_records = [row.asDict() for row in scored_df.limit(500).collect()]
            for rec in top_records:
                rec["updated_at"] = datetime.now().isoformat()

            db[col_name].delete_many({})
            db[col_name].insert_many(top_records)
            print(f"  [OK] Exported {len(top_records)} threat reputation profiles to '{col_name}'.")
            client.close()
        except Exception as e:
            print(f"[-] MongoDB export note: {e}")

    duration = time.time() - start_time
    print("=" * 65)
    print(f"[OK] Evaluated {scored_count:,} unique IP profiles in {duration:.2f}s.")
    print("=" * 65)

    spark.stop()
    return scored_df


def lookup_ip(ip_address: str):
    scores_file = PATH_CONFIG["processed_data_dir"] / "ip_risk_scores.parquet"
    if not scores_file.exists():
        compute_ip_risk_scores()

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    df = spark.read.parquet(str(scores_file))
    match = df.filter(col("source_ip") == ip_address).collect()

    print("=" * 65)
    print(f"          THREAT INTEL PROFILE: {ip_address}")
    print("=" * 65)
    if match:
        row = match[0]
        print(f"IP Address:           {row.source_ip}")
        print(f"Total Flows:          {row.total_flows}")
        print(f"Total Attacks:        {row.attack_count}")
        print(f"Target Scope:         {row.unique_destinations} distinct targets")
        print(f"Risk Score (0-100):   {row.risk_score}")
        print(f"Threat Tier:          {row.risk_level.upper()}")
        print(f"Defense Policy:       {row.recommended_action}")
    else:
        print(f"[!] IP {ip_address} has not been observed in network telemetry.")
    print("=" * 65)

    spark.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate IP Risk Scores or lookup IP profile.")
    parser.add_argument("--ip", type=str, help="Lookup threat intelligence profile for specific IP")
    parser.add_argument("--mongo", action="store_true", help="Store scores into MongoDB Atlas")
    args = parser.parse_args()

    if args.ip:
        lookup_ip(args.ip)
    else:
        compute_ip_risk_scores(write_mongo=args.mongo)
