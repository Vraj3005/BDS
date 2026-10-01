"""
Spark Analytics Job: IP Threat Frequency & Network Timeline Analysis
Distributed Cyber Threat Intelligence Platform - Phase 7

Produces two families of aggregations:

ip_analysis.py (this file):
  1. Top attacking source IPs (by attack-flow count + total bytes sent).
  2. Top targeted destination IPs (by attack-flow count).
  3. Source-IP × Attack-Type cross-tab (top attacker per attack category).

timeline_analysis.py logic is also included here as a second entry-point
  so both commit messages map to a single cohesive analytics module:
  4. Hourly network timeline (all traffic vs attack traffic).
  5. Daily (day-of-week) attack cadence.
  6. Rolling 6-hour attack surge detection.

Results are persisted to Parquet and optionally to MongoDB collections.
"""

import os
import sys
import json
import time
from pathlib import Path

os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG, MONGO_CONFIG, get_spark_master_url, get_mongo_uri
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import (
    col, count, desc, when, avg, spark_partition_id,
    sum as spark_sum, round as spark_round, lit,
    broadcast, max as spark_max, min as spark_min
)


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

def get_spark_session(app_name: str = "CyberThreat-IPAnalysis") -> SparkSession:
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
# Helper: write collected rows to MongoDB
# ---------------------------------------------------------------------------

def _write_to_mongo(df, collection_name: str) -> int:
    """Persist Spark DataFrame to MongoDB via PyMongo."""
    from pymongo import MongoClient
    records = [row.asDict() for row in df.collect()]
    if not records:
        print(f"  [WARN] No records to write to '{collection_name}'.")
        return 0

    uri = get_mongo_uri()
    kwargs = {"serverSelectionTimeoutMS": 10_000}
    try:
        import certifi
        kwargs["tlsCAFile"] = certifi.where()
    except Exception:
        pass

    try:
        client = MongoClient(uri, **kwargs)
        db = client[MONGO_CONFIG["db_name"]]
        coll = db[collection_name]
        coll.drop()
        coll.insert_many(records)
        client.close()
        print(f"  [OK] {len(records)} docs -> MongoDB '{collection_name}'.")
    except Exception as exc:
        print(f"  [WARN] MongoDB write skipped ({exc}). Parquet output still saved.")
        return 0
    return len(records)


# ===========================================================================
# IP ANALYSIS -- source / destination IP aggregations
# ===========================================================================

def compute_top_attacking_ips(df, top_n: int = 50):
    """
    Return top N source IPs ranked by total attack-flow count.

    Columns: source_ip | attack_flow_count | total_bytes_sent_mb |
             unique_attack_types | avg_packet_length | top_attack_type
    """
    attack_df = df.filter(col("attack_type") != "BENIGN")

    # Most frequent attack type per IP (approximate via mode aggregation)
    type_counts = (
        attack_df.groupBy("source_ip", "attack_type")
        .agg(count("*").alias("_cnt"))
    )
    from pyspark.sql.window import Window
    w = Window.partitionBy("source_ip").orderBy(desc("_cnt"))
    top_type = (
        type_counts
        .withColumn("_rank", F.row_number().over(w))
        .filter(col("_rank") == 1)
        .select("source_ip", col("attack_type").alias("top_attack_type"))
    )

    agg_df = (
        attack_df.groupBy("source_ip")
        .agg(
            count("*").alias("attack_flow_count"),
            spark_round(
                spark_sum("total_bytes") / lit(1_048_576), 4
            ).alias("total_bytes_sent_mb"),
            F.countDistinct("attack_type").alias("unique_attack_types"),
            spark_round(avg("packet_length"), 2).alias("avg_packet_length"),
        )
        .join(top_type, on="source_ip", how="left")
        .orderBy(desc("attack_flow_count"))
        .limit(top_n)
    )
    return agg_df


def compute_top_targeted_ips(df, top_n: int = 50):
    """
    Return top N destination IPs most frequently targeted by attacks.

    Columns: destination_ip | attack_flow_count | unique_attackers |
             unique_attack_types | total_bytes_received_mb
    """
    attack_df = df.filter(col("attack_type") != "BENIGN")
    agg_df = (
        attack_df.groupBy("destination_ip")
        .agg(
            count("*").alias("attack_flow_count"),
            F.countDistinct("source_ip").alias("unique_attackers"),
            F.countDistinct("attack_type").alias("unique_attack_types"),
            spark_round(
                spark_sum("total_bytes") / lit(1_048_576), 4
            ).alias("total_bytes_received_mb"),
        )
        .orderBy(desc("attack_flow_count"))
        .limit(top_n)
    )
    return agg_df


def compute_ip_attack_crosstab(df, top_ips: int = 20):
    """
    For the top N source IPs, produce a cross-tab of attack_type counts.

    Columns: source_ip | <attack_type_1> | <attack_type_2> | ...
    """
    attack_df = df.filter(col("attack_type") != "BENIGN")

    # Identify top IPs
    top_ip_list = [
        r["source_ip"] for r in
        attack_df.groupBy("source_ip")
        .agg(count("*").alias("_c"))
        .orderBy(desc("_c"))
        .limit(top_ips)
        .select("source_ip")
        .collect()
    ]

    filtered = attack_df.filter(col("source_ip").isin(top_ip_list))
    pivot = (
        filtered.groupBy("source_ip")
        .pivot("attack_type")
        .count()
        .fillna(0)
        .orderBy("source_ip")
    )
    return pivot


# ===========================================================================
# TIMELINE ANALYSIS -- temporal aggregations
# ===========================================================================

def compute_hourly_timeline(df):
    """
    Full 24-hour timeline of total flows vs. attack flows.

    Columns: hour | total_flows | attack_flows | benign_flows |
             attack_rate_pct | avg_flow_duration_ms
    """
    timeline = (
        df.groupBy("hour")
        .agg(
            count("*").alias("total_flows"),
            count(when(col("attack_type") != "BENIGN", True)).alias("attack_flows"),
            count(when(col("attack_type") == "BENIGN", True)).alias("benign_flows"),
            spark_round(avg("flow_duration"), 2).alias("avg_flow_duration_ms"),
        )
        .withColumn(
            "attack_rate_pct",
            spark_round(
                col("attack_flows") / col("total_flows") * lit(100), 2
            )
        )
        .orderBy("hour")
    )
    return timeline


def compute_daily_cadence(df):
    """
    Day-of-week attack cadence (1=Sunday … 7=Saturday in Spark).

    Columns: day_of_week | day_name | total_flows | attack_flows |
             unique_attack_types | attack_rate_pct
    """
    day_names = {1: "Sunday", 2: "Monday", 3: "Tuesday", 4: "Wednesday",
                 5: "Thursday", 6: "Friday", 7: "Saturday"}

    day_name_expr = F.create_map(
        *[item for pair in
          [(lit(k), lit(v)) for k, v in day_names.items()]
          for item in pair]
    )

    cadence = (
        df.groupBy("day_of_week")
        .agg(
            count("*").alias("total_flows"),
            count(when(col("attack_type") != "BENIGN", True)).alias("attack_flows"),
            F.countDistinct("attack_type").alias("unique_attack_types"),
        )
        .withColumn("day_name", day_name_expr[col("day_of_week")])
        .withColumn(
            "attack_rate_pct",
            spark_round(
                col("attack_flows") / col("total_flows") * lit(100), 2
            )
        )
        .orderBy("day_of_week")
    )
    return cadence


def compute_peak_surge_windows(df):
    """
    Identify 6-hour windows (0-5, 6-11, 12-17, 18-23) with highest attack load.

    Columns: surge_window | hour_range | attack_flows | total_flows | attack_rate_pct
    """
    bucketed = df.withColumn(
        "surge_window",
        when(col("hour") < 6,  lit("00-05"))
        .when(col("hour") < 12, lit("06-11"))
        .when(col("hour") < 18, lit("12-17"))
        .otherwise(lit("18-23"))
    )
    surge = (
        bucketed.groupBy("surge_window")
        .agg(
            count("*").alias("total_flows"),
            count(when(col("attack_type") != "BENIGN", True)).alias("attack_flows"),
        )
        .withColumn(
            "attack_rate_pct",
            spark_round(
                col("attack_flows") / col("total_flows") * lit(100), 2
            )
        )
        .orderBy(desc("attack_flows"))
    )
    return surge


# ===========================================================================
# Main orchestrators
# ===========================================================================

def run_ip_analysis(
    cleaned_parquet: Path = None,
    output_dir: Path = None,
    write_mongo: bool = True,
    top_n: int = 50,
) -> dict:
    """
    Run all IP-level threat frequency aggregations.

    Returns:
        dict of summary counts per aggregation.
    """
    input_path = cleaned_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")
    out_dir    = output_dir      or PATH_CONFIG["processed_data_dir"]

    if not Path(input_path).exists():
        print(f"[-] Cleaned dataset not found. Running ETL first...")
        from spark.preprocessing.clean_logs import clean_network_logs
        clean_network_logs()

    spark = get_spark_session("CyberThreat-IPAnalysis")
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("      PHASE 7 -- IP THREAT FREQUENCY ANALYSIS")
    print("=" * 65)
    print(f"  Source : {input_path}")
    print(f"  Output : {out_dir}")
    print("=" * 65)

    start = time.time()
    df = spark.read.parquet(str(input_path))
    total = df.count()
    print(f"\n  [OK] {total:,} records loaded.")

    results = {}

    # -- Top attacking source IPs -----------------------------------------
    print(f"\n[Step 1/3] Top {top_n} attacking source IPs...")
    src_df = compute_top_attacking_ips(df, top_n)
    src_count = src_df.count()
    src_df.show(10, truncate=False)

    p = Path(out_dir) / "top_attacking_ips.parquet"
    src_df.write.mode("overwrite").parquet(str(p))
    print(f"  [OK] {src_count} rows -> {p}")
    results["top_attacking_ips"] = src_count

    if write_mongo:
        _write_to_mongo(src_df, "ip_threat_frequency")

    # -- Top targeted destination IPs -------------------------------------
    print(f"\n[Step 2/3] Top {top_n} targeted destination IPs...")
    dst_df = compute_top_targeted_ips(df, top_n)
    dst_count = dst_df.count()
    dst_df.show(10, truncate=False)

    p = Path(out_dir) / "top_targeted_ips.parquet"
    dst_df.write.mode("overwrite").parquet(str(p))
    print(f"  [OK] {dst_count} rows -> {p}")
    results["top_targeted_ips"] = dst_count

    # -- IP × Attack-type cross-tab ---------------------------------------
    print("\n[Step 3/3] IP × Attack-Type cross-tab...")
    pivot_df = compute_ip_attack_crosstab(df)
    pivot_count = pivot_df.count()
    pivot_df.show(10, truncate=True)

    p = Path(out_dir) / "ip_attack_crosstab.parquet"
    pivot_df.write.mode("overwrite").parquet(str(p))
    print(f"  [OK] {pivot_count} rows -> {p}")
    results["ip_attack_crosstab_rows"] = pivot_count

    elapsed = time.time() - start
    results.update({"total_records": total, "execution_time_s": round(elapsed, 2)})

    print("\n" + "=" * 65)
    print("           IP THREAT ANALYSIS -- SUMMARY")
    print("=" * 65)
    print(f"  Total Records Analysed:   {total:,}")
    print(f"  Top Attacking IPs:        {src_count}")
    print(f"  Top Targeted IPs:         {dst_count}")
    print(f"  Cross-tab Rows:           {pivot_count}")
    print(f"  Execution Time:           {elapsed:.2f}s")
    print("=" * 65)

    spark.stop()
    return results


def run_timeline_analysis(
    cleaned_parquet: Path = None,
    output_dir: Path = None,
    write_mongo: bool = True,
) -> dict:
    """
    Run all temporal network timeline aggregations.

    Returns:
        dict of summary counts per aggregation.
    """
    input_path = cleaned_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")
    out_dir    = output_dir      or PATH_CONFIG["processed_data_dir"]

    if not Path(input_path).exists():
        print(f"[-] Cleaned dataset not found. Running ETL first...")
        from spark.preprocessing.clean_logs import clean_network_logs
        clean_network_logs()

    spark = get_spark_session("CyberThreat-TimelineAnalysis")
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("     PHASE 7 -- NETWORK TIMELINE ANALYSIS")
    print("=" * 65)
    print(f"  Source : {input_path}")
    print(f"  Output : {out_dir}")
    print("=" * 65)

    start = time.time()
    df = spark.read.parquet(str(input_path))
    total = df.count()
    print(f"\n  [OK] {total:,} records loaded.")

    results = {}

    # -- Hourly timeline --------------------------------------------------
    print("\n[Step 1/3] Computing 24-hour network timeline...")
    hourly = compute_hourly_timeline(df)
    hourly_count = hourly.count()
    hourly.show(24, truncate=False)

    p = Path(out_dir) / "network_timeline_hourly.parquet"
    hourly.write.mode("overwrite").parquet(str(p))
    print(f"  [OK] {hourly_count} hourly rows -> {p}")
    results["hourly_timeline_rows"] = hourly_count

    if write_mongo:
        _write_to_mongo(hourly, MONGO_CONFIG["collections"]["timeline_stats"])

    # -- Daily cadence ----------------------------------------------------
    print("\n[Step 2/3] Computing day-of-week attack cadence...")
    daily = compute_daily_cadence(df)
    daily_count = daily.count()
    daily.show(7, truncate=False)

    p = Path(out_dir) / "network_timeline_daily.parquet"
    daily.write.mode("overwrite").parquet(str(p))
    print(f"  [OK] {daily_count} daily rows -> {p}")
    results["daily_cadence_rows"] = daily_count

    # -- 6-hour surge windows --------------------------------------------
    print("\n[Step 3/3] Computing 6-hour peak surge windows...")
    surge = compute_peak_surge_windows(df)
    surge_count = surge.count()
    surge.show(truncate=False)

    p = Path(out_dir) / "attack_surge_windows.parquet"
    surge.write.mode("overwrite").parquet(str(p))
    print(f"  [OK] {surge_count} surge windows -> {p}")
    results["surge_window_rows"] = surge_count

    elapsed = time.time() - start
    results.update({"total_records": total, "execution_time_s": round(elapsed, 2)})

    print("\n" + "=" * 65)
    print("           TIMELINE ANALYSIS -- SUMMARY")
    print("=" * 65)
    print(f"  Total Records Analysed:   {total:,}")
    print(f"  Hourly Buckets:           {hourly_count}")
    print(f"  Daily Cadence Rows:       {daily_count}")
    print(f"  Surge Windows:            {surge_count}")
    print(f"  Execution Time:           {elapsed:.2f}s")
    print("=" * 65)

    spark.stop()
    return results


# ---------------------------------------------------------------------------
# CLI: run both analyses when executed directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Phase 7 -- IP & Timeline Analytics"
    )
    parser.add_argument(
        "--mode", choices=["ip", "timeline", "both"], default="both",
        help="Which analysis to run (default: both)"
    )
    args = parser.parse_args()

    if args.mode in ("ip", "both"):
        run_ip_analysis()

    if args.mode in ("timeline", "both"):
        run_timeline_analysis()
