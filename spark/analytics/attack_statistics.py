"""
Spark Analytics Job: Attack Statistics & Distribution Aggregation
Distributed Cyber Threat Intelligence Platform - Phase 7

Aggregates cleaned network logs to produce:
1. Per-attack-type count, percentage share, and average severity score.
2. Protocol distribution breakdown across all traffic.
3. Hourly attack intensity bucketed across the 24-hour cycle.
4. Severity-level distribution (Critical / High / Medium / Low).
5. Writes results to MongoDB 'attack_stats' collection and Parquet.
"""

import os
import sys
import json
import time
from pathlib import Path

# Ensure consistent Python runtime across Spark driver and workers
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG, MONGO_CONFIG, get_spark_master_url, get_mongo_uri
from pyspark.sql import SparkSession, Window
from pyspark.sql import functions as F
from pyspark.sql.functions import (
    col, count, round as spark_round, lit,
    when, avg, sum as spark_sum,
    desc, rank, broadcast
)


# ---------------------------------------------------------------------------
# Severity → numeric score mapping
# ---------------------------------------------------------------------------
SEVERITY_SCORES = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def get_spark_session(app_name: str = "CyberThreat-AttackStats") -> SparkSession:
    """Build and return a local SparkSession for analytics."""
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


# ---------------------------------------------------------------------------
# Helper: write a Spark DataFrame to MongoDB
# ---------------------------------------------------------------------------
def _write_to_mongo(df, collection_name: str) -> int:
    """Persist a Spark DataFrame to MongoDB via PyMongo (collect + bulk write)."""
    from pymongo import MongoClient, ReplaceOne
    import certifi

    records = [row.asDict() for row in df.collect()]
    if not records:
        print(f"  [WARN] No records to write to '{collection_name}'.")
        return 0

    uri = get_mongo_uri()
    kwargs = {"serverSelectionTimeoutMS": 10_000}
    try:
        kwargs["tlsCAFile"] = certifi.where()
    except Exception:
        pass

    try:
        client = MongoClient(uri, **kwargs)
        db = client[MONGO_CONFIG["db_name"]]
        coll = db[collection_name]
        coll.drop()                       # full refresh each run
        coll.insert_many(records)
        client.close()
        print(f"  [OK] {len(records)} documents written to MongoDB '{collection_name}'.")
    except Exception as exc:
        print(f"  [WARN] MongoDB write skipped ({exc}). Continuing without persistence.")
        records = []
    return len(records)


# ---------------------------------------------------------------------------
# Core analytics functions
# ---------------------------------------------------------------------------

def compute_attack_distribution(df) -> "DataFrame":
    """
    Return a DataFrame with per-attack-type statistics:
      attack_type | total_flows | pct_share | avg_severity_score |
      avg_flow_duration_ms | avg_packet_length | total_bytes_gb
    """
    total = df.count()

    severity_map_df = (
        df.sparkSession.createDataFrame(
            list(SEVERITY_SCORES.items()), ["severity", "severity_score"]
        )
    )

    scored = df.join(broadcast(severity_map_df), on="severity", how="left")

    stats = (
        scored.groupBy("attack_type")
        .agg(
            count("*").alias("total_flows"),
            spark_round(
                count("*") / lit(total) * lit(100), 2
            ).alias("pct_share"),
            spark_round(avg("severity_score"), 2).alias("avg_severity_score"),
            spark_round(avg("flow_duration"),  2).alias("avg_flow_duration_ms"),
            spark_round(avg("packet_length"),  2).alias("avg_packet_length"),
            spark_round(
                spark_sum("total_bytes") / lit(1_073_741_824), 6
            ).alias("total_bytes_gb"),
        )
        .orderBy(desc("total_flows"))
    )
    return stats


def compute_protocol_distribution(df) -> "DataFrame":
    """
    Return protocol-level breakdown:
      protocol | total_flows | pct_share | attack_count | benign_count
    """
    total = df.count()
    proto = (
        df.groupBy("protocol")
        .agg(
            count("*").alias("total_flows"),
            spark_round(count("*") / lit(total) * lit(100), 2).alias("pct_share"),
            count(when(col("attack_type") != "BENIGN", True)).alias("attack_count"),
            count(when(col("attack_type") == "BENIGN", True)).alias("benign_count"),
        )
        .orderBy(desc("total_flows"))
    )
    return proto


def compute_hourly_attack_intensity(df) -> "DataFrame":
    """
    Return hourly (0-23) aggregated attack counts:
      hour | total_flows | attack_flows | benign_flows | attack_rate_pct
    """
    hourly = (
        df.groupBy("hour")
        .agg(
            count("*").alias("total_flows"),
            count(when(col("attack_type") != "BENIGN", True)).alias("attack_flows"),
            count(when(col("attack_type") == "BENIGN", True)).alias("benign_flows"),
        )
        .withColumn(
            "attack_rate_pct",
            spark_round(col("attack_flows") / col("total_flows") * lit(100), 2)
        )
        .orderBy("hour")
    )
    return hourly


def compute_severity_distribution(df) -> "DataFrame":
    """
    Return severity-level totals:
      severity | total_flows | pct_share
    """
    total = df.count()
    sev = (
        df.groupBy("severity")
        .agg(
            count("*").alias("total_flows"),
            spark_round(count("*") / lit(total) * lit(100), 2).alias("pct_share"),
        )
        .orderBy(desc("total_flows"))
    )
    return sev


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------

def run_attack_statistics(
    cleaned_parquet: Path = None,
    output_dir: Path = None,
    write_mongo: bool = True,
) -> dict:
    """
    Execute all attack-distribution aggregations and persist results.

    Args:
        cleaned_parquet: Path to cleaned Parquet (defaults to processed_data_dir).
        output_dir:      Directory for Parquet outputs (defaults to processed_data_dir).
        write_mongo:     If True, attempt to write results to MongoDB.

    Returns:
        dict with summary counts for each aggregation.
    """
    input_path  = cleaned_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")
    out_dir     = output_dir      or PATH_CONFIG["processed_data_dir"]

    if not Path(input_path).exists():
        print(f"[-] Cleaned dataset not found at {input_path}. Running ETL first...")
        from spark.preprocessing.clean_logs import clean_network_logs
        clean_network_logs()

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("    PHASE 7 — ATTACK STATISTICS & DISTRIBUTION AGGREGATION")
    print("=" * 65)
    print(f"  Source: {input_path}")
    print(f"  Output: {out_dir}")
    print("=" * 65)

    start = time.time()

    # Load cleaned dataset
    print("\n[Step 1/5] Loading cleaned network log dataset...")
    df = spark.read.parquet(str(input_path))
    total_records = df.count()
    print(f"  [OK] {total_records:,} records loaded.")

    results = {}

    # ------------------------------------------------------------------
    # Aggregation 1: Per-attack-type distribution
    # ------------------------------------------------------------------
    print("\n[Step 2/5] Computing per-attack-type statistics...")
    attack_dist = compute_attack_distribution(df)
    attack_count = attack_dist.count()
    attack_dist.show(20, truncate=False)

    out_path = Path(out_dir) / "attack_distribution.parquet"
    attack_dist.write.mode("overwrite").parquet(str(out_path))
    print(f"  [OK] {attack_count} attack-type aggregations saved → {out_path}")
    results["attack_distribution_rows"] = attack_count

    if write_mongo:
        _write_to_mongo(
            attack_dist, MONGO_CONFIG["collections"]["attack_stats"]
        )

    # ------------------------------------------------------------------
    # Aggregation 2: Protocol distribution
    # ------------------------------------------------------------------
    print("\n[Step 3/5] Computing protocol distribution...")
    proto_dist = compute_protocol_distribution(df)
    proto_count = proto_dist.count()
    proto_dist.show(truncate=False)

    out_path = Path(out_dir) / "protocol_distribution.parquet"
    proto_dist.write.mode("overwrite").parquet(str(out_path))
    print(f"  [OK] {proto_count} protocol aggregations saved → {out_path}")
    results["protocol_distribution_rows"] = proto_count

    # ------------------------------------------------------------------
    # Aggregation 3: Hourly attack intensity
    # ------------------------------------------------------------------
    print("\n[Step 4/5] Computing hourly attack intensity (0-23h buckets)...")
    hourly = compute_hourly_attack_intensity(df)
    hourly_count = hourly.count()
    hourly.show(24, truncate=False)

    out_path = Path(out_dir) / "hourly_attack_intensity.parquet"
    hourly.write.mode("overwrite").parquet(str(out_path))
    print(f"  [OK] {hourly_count} hourly buckets saved → {out_path}")
    results["hourly_intensity_rows"] = hourly_count

    # ------------------------------------------------------------------
    # Aggregation 4: Severity distribution
    # ------------------------------------------------------------------
    print("\n[Step 5/5] Computing severity-level distribution...")
    sev_dist = compute_severity_distribution(df)
    sev_count = sev_dist.count()
    sev_dist.show(truncate=False)

    out_path = Path(out_dir) / "severity_distribution.parquet"
    sev_dist.write.mode("overwrite").parquet(str(out_path))
    print(f"  [OK] {sev_count} severity levels saved → {out_path}")
    results["severity_distribution_rows"] = sev_count

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    elapsed = time.time() - start
    results["total_records_analysed"] = total_records
    results["execution_time_s"]       = round(elapsed, 2)

    summary_path = Path(out_dir) / "attack_stats_summary.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    print("\n" + "=" * 65)
    print("              ATTACK STATISTICS — SUMMARY")
    print("=" * 65)
    print(f"  Total Records Analysed:      {total_records:,}")
    print(f"  Attack-Type Categories:      {attack_count}")
    print(f"  Protocol Types:              {proto_count}")
    print(f"  Hourly Buckets:              {hourly_count}")
    print(f"  Severity Levels:             {sev_count}")
    print(f"  Execution Time:              {elapsed:.2f}s")
    print(f"  Summary JSON:                {summary_path}")
    print("=" * 65)

    spark.stop()
    return results


if __name__ == "__main__":
    run_attack_statistics()
