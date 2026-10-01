"""
Phase 10 -- Spark Analytics & ML Inference Integration
Distributed Cyber Threat Intelligence Platform

Bridges all upstream Spark/ML pipeline outputs into MongoDB so the
Streamlit dashboard can consume live, aggregated threat intelligence.

Operations performed (in order):
  1. Attack distribution stats        -> MongoDB 'attack_stats'
  2. Protocol distribution            -> MongoDB 'protocol_stats'
  3. Hourly attack intensity          -> MongoDB 'hourly_stats'
  4. Severity distribution            -> MongoDB 'severity_stats'
  5. Top attacking source IPs         -> MongoDB 'ip_threat_frequency'
  6. Top targeted destination IPs     -> MongoDB 'top_targeted_ips'
  7. Network timeline (hourly)        -> MongoDB 'timeline_stats'
  8. IP risk / reputation scores      -> MongoDB 'ip_reputation'
  9. ML intrusion predictions         -> MongoDB 'predictions'
 10. Model performance metrics        -> MongoDB 'model_metrics'
 11. Integration manifest             -> MongoDB 'integration_log'

Usage:
    python spark/jobs/integrate_results.py [--force-rerun]
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Environment bootstrap
# ---------------------------------------------------------------------------
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG, MONGO_CONFIG, get_spark_master_url, get_mongo_client

try:
    from pyspark.sql import SparkSession
    from pyspark.sql.functions import col, count, when
    SPARK_AVAILABLE = True
except ImportError:
    SPARK_AVAILABLE = False


# ---------------------------------------------------------------------------
# Spark session factory (shared across all integration tasks)
# ---------------------------------------------------------------------------

def _get_spark(app_name: str = "CyberThreat-Integration") -> "SparkSession":
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
# MongoDB helpers
# ---------------------------------------------------------------------------

def _mongo_upsert_collection(records: list, collection_name: str) -> int:
    """Drop-and-replace a MongoDB collection with the given records."""
    if not records:
        print(f"  [SKIP] No records to write to '{collection_name}'.")
        return 0
    try:
        client = get_mongo_client()
        db = client[MONGO_CONFIG["db_name"]]
        coll = db[collection_name]
        coll.drop()
        coll.insert_many(records)
        client.close()
        print(f"  [OK]  {len(records):>6,} documents -> MongoDB '{collection_name}'.")
        return len(records)
    except Exception as exc:
        print(f"  [WARN] MongoDB write failed for '{collection_name}': {exc}")
        return 0


def _parquet_to_mongo(spark, parquet_path: Path, collection_name: str) -> int:
    """Read a Parquet file with Spark and push all rows to MongoDB."""
    if not parquet_path.exists():
        print(f"  [SKIP] Parquet not found: {parquet_path}")
        return 0
    df = spark.read.parquet(str(parquet_path))
    records = [row.asDict() for row in df.collect()]
    return _mongo_upsert_collection(records, collection_name)


# ---------------------------------------------------------------------------
# Phase 10 — individual integration tasks
# ---------------------------------------------------------------------------

def _integrate_attack_stats(spark, proc_dir: Path, results: dict) -> None:
    """Commit 17a: attack distribution -> attack_stats."""
    print("\n[Task 1/10] Integrating attack distribution statistics...")
    n = _parquet_to_mongo(
        spark,
        proc_dir / "attack_distribution.parquet",
        MONGO_CONFIG["collections"]["attack_stats"],
    )
    results["attack_stats_docs"] = n


def _integrate_protocol_stats(spark, proc_dir: Path, results: dict) -> None:
    """Protocol distribution -> protocol_stats."""
    print("\n[Task 2/10] Integrating protocol distribution...")
    n = _parquet_to_mongo(spark, proc_dir / "protocol_distribution.parquet", "protocol_stats")
    results["protocol_stats_docs"] = n


def _integrate_hourly_stats(spark, proc_dir: Path, results: dict) -> None:
    """Hourly attack intensity -> hourly_stats."""
    print("\n[Task 3/10] Integrating hourly attack intensity...")
    n = _parquet_to_mongo(spark, proc_dir / "hourly_attack_intensity.parquet", "hourly_stats")
    results["hourly_stats_docs"] = n


def _integrate_severity_stats(spark, proc_dir: Path, results: dict) -> None:
    """Severity distribution -> severity_stats."""
    print("\n[Task 4/10] Integrating severity distribution...")
    n = _parquet_to_mongo(spark, proc_dir / "severity_distribution.parquet", "severity_stats")
    results["severity_stats_docs"] = n


def _integrate_ip_threat_frequency(spark, proc_dir: Path, results: dict) -> None:
    """Top attacking IPs -> ip_threat_frequency."""
    print("\n[Task 5/10] Integrating top attacking source IPs...")
    n = _parquet_to_mongo(spark, proc_dir / "top_attacking_ips.parquet", "ip_threat_frequency")
    results["ip_threat_frequency_docs"] = n


def _integrate_top_targeted_ips(spark, proc_dir: Path, results: dict) -> None:
    """Top targeted IPs -> top_targeted_ips."""
    print("\n[Task 6/10] Integrating top targeted destination IPs...")
    n = _parquet_to_mongo(spark, proc_dir / "top_targeted_ips.parquet", "top_targeted_ips")
    results["top_targeted_ips_docs"] = n


def _integrate_timeline_stats(spark, proc_dir: Path, results: dict) -> None:
    """Network hourly timeline -> timeline_stats."""
    print("\n[Task 7/10] Integrating network timeline (hourly)...")
    n = _parquet_to_mongo(
        spark,
        proc_dir / "network_timeline_hourly.parquet",
        MONGO_CONFIG["collections"]["timeline_stats"],
    )
    results["timeline_stats_docs"] = n


def _integrate_ip_reputation(spark, proc_dir: Path, results: dict) -> None:
    """IP risk scores -> ip_reputation."""
    print("\n[Task 8/10] Integrating IP risk reputation scores...")
    n = _parquet_to_mongo(
        spark,
        proc_dir / "ip_risk_scores.parquet",
        MONGO_CONFIG["collections"]["ip_reputation"],
    )
    results["ip_reputation_docs"] = n


def _integrate_predictions(spark, proc_dir: Path, results: dict) -> None:
    """ML intrusion predictions sample -> predictions."""
    print("\n[Task 9/10] Integrating ML intrusion predictions...")
    features_path = proc_dir / "features.parquet"
    model_path = PATH_CONFIG["models_dir"] / "rf_threat_model"

    if not features_path.exists() or not model_path.exists():
        print("  [SKIP] features.parquet or rf_threat_model not found. Skipping predictions.")
        results["predictions_docs"] = 0
        return

    try:
        from pyspark.ml.classification import RandomForestClassificationModel

        label_file = PATH_CONFIG["models_dir"] / "label_mapping.json"
        if label_file.exists():
            with open(label_file, "r", encoding="utf-8") as f:
                label_map = {int(k): v for k, v in json.load(f).items()}
        else:
            label_map = {0: "PortScan", 1: "DDoS", 2: "BENIGN", 3: "BruteForce", 4: "Botnet"}

        model = RandomForestClassificationModel.load(str(model_path))
        df = spark.read.parquet(str(features_path))
        preds = model.transform(df).limit(500)

        mongo_records = []
        for row in preds.collect():
            pred_idx = int(row.prediction)
            pred_attack = label_map.get(pred_idx, f"Unknown_{pred_idx}")
            prob_array = row.probability.toArray()
            confidence = round(float(prob_array[pred_idx]) * 100, 2)
            mongo_records.append({
                "source_ip": getattr(row, "source_ip", "N/A"),
                "destination_ip": getattr(row, "destination_ip", "N/A"),
                "actual_attack": getattr(row, "attack_type", "N/A"),
                "predicted_attack": pred_attack,
                "confidence": confidence,
                "analyzed_at": datetime.now().isoformat(),
            })

        n = _mongo_upsert_collection(mongo_records, MONGO_CONFIG["collections"]["predictions"])
        results["predictions_docs"] = n
    except Exception as exc:
        print(f"  [WARN] Prediction integration failed: {exc}")
        results["predictions_docs"] = 0


def _integrate_model_metrics(results: dict) -> None:
    """Model metrics JSON -> model_metrics collection."""
    print("\n[Task 10/10] Integrating ML model performance metrics...")
    metrics_file = PATH_CONFIG["models_dir"] / "model_metrics.json"
    if not metrics_file.exists():
        print("  [SKIP] model_metrics.json not found.")
        results["model_metrics_docs"] = 0
        return

    with open(metrics_file, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Also embed confusion matrix if available
    cm_file = PATH_CONFIG["models_dir"] / "confusion_matrix.json"
    if cm_file.exists():
        with open(cm_file, "r", encoding="utf-8") as f:
            raw["confusion_matrix_summary"] = json.load(f)

    raw["integrated_at"] = datetime.now().isoformat()
    n = _mongo_upsert_collection([raw], "model_metrics")
    results["model_metrics_docs"] = n


# ---------------------------------------------------------------------------
# Upstream pipeline launchers (if outputs are missing)
# ---------------------------------------------------------------------------

def _ensure_analytics_outputs(proc_dir: Path, force: bool) -> None:
    """Re-run upstream Spark analytics jobs if Parquet outputs are absent."""
    required = [
        "attack_distribution.parquet",
        "protocol_distribution.parquet",
        "hourly_attack_intensity.parquet",
        "severity_distribution.parquet",
    ]
    missing = [r for r in required if not (proc_dir / r).exists()]
    if missing or force:
        print("\n[*] Running Phase 7 attack statistics job...")
        from spark.analytics.attack_statistics import run_attack_statistics
        run_attack_statistics(write_mongo=False)


def _ensure_ip_outputs(proc_dir: Path, force: bool) -> None:
    """Re-run IP analysis if outputs are missing."""
    required = ["top_attacking_ips.parquet", "top_targeted_ips.parquet"]
    missing = [r for r in required if not (proc_dir / r).exists()]
    if missing or force:
        print("\n[*] Running Phase 7 IP threat analysis job...")
        from spark.analytics.ip_timeline_analysis import run_ip_analysis
        run_ip_analysis(write_mongo=False)


def _ensure_timeline_outputs(proc_dir: Path, force: bool) -> None:
    """Re-run timeline analysis if output is missing."""
    if not (proc_dir / "network_timeline_hourly.parquet").exists() or force:
        print("\n[*] Running Phase 7 timeline analysis job...")
        from spark.analytics.ip_timeline_analysis import run_timeline_analysis
        run_timeline_analysis(write_mongo=False)


def _ensure_risk_scores(proc_dir: Path, force: bool) -> None:
    """Re-run IP risk engine if output is missing."""
    if not (proc_dir / "ip_risk_scores.parquet").exists() or force:
        print("\n[*] Running Phase 9 IP risk scoring engine...")
        from ml.risk_engine.calculate_risk import compute_ip_risk_scores
        compute_ip_risk_scores(write_mongo=False)


# ---------------------------------------------------------------------------
# Main integration orchestrator
# ---------------------------------------------------------------------------

def run_integration(force_rerun: bool = False) -> dict:
    """
    Execute all Phase 10 integration tasks sequentially.

    Args:
        force_rerun: If True, re-run all upstream Spark jobs before integrating.

    Returns:
        dict summary of documents written per collection.
    """
    proc_dir = PATH_CONFIG["processed_data_dir"]
    proc_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 65)
    print("  PHASE 10 -- SPARK ANALYTICS & ML INTEGRATION INTO MONGODB")
    print("=" * 65)
    print(f"  Database:       {MONGO_CONFIG['db_name']}")
    print(f"  Processed Dir:  {proc_dir}")
    print(f"  Force Rerun:    {force_rerun}")
    print("=" * 65)

    start = time.time()
    results: dict = {}

    # -----------------------------------------------------------------------
    # Ensure upstream Parquet outputs exist
    # -----------------------------------------------------------------------
    print("\n[Pre-flight] Verifying upstream Parquet pipeline outputs...")
    _ensure_analytics_outputs(proc_dir, force_rerun)
    _ensure_ip_outputs(proc_dir, force_rerun)
    _ensure_timeline_outputs(proc_dir, force_rerun)
    _ensure_risk_scores(proc_dir, force_rerun)

    # -----------------------------------------------------------------------
    # Start Spark session (used to read Parquet)
    # -----------------------------------------------------------------------
    if not SPARK_AVAILABLE:
        print("[ERROR] PySpark is not installed. Cannot read Parquet files.")
        return results

    spark = _get_spark()
    spark.sparkContext.setLogLevel("WARN")

    # -----------------------------------------------------------------------
    # Execute all integration tasks
    # -----------------------------------------------------------------------
    _integrate_attack_stats(spark, proc_dir, results)
    _integrate_protocol_stats(spark, proc_dir, results)
    _integrate_hourly_stats(spark, proc_dir, results)
    _integrate_severity_stats(spark, proc_dir, results)
    _integrate_ip_threat_frequency(spark, proc_dir, results)
    _integrate_top_targeted_ips(spark, proc_dir, results)
    _integrate_timeline_stats(spark, proc_dir, results)
    _integrate_ip_reputation(spark, proc_dir, results)
    _integrate_predictions(spark, proc_dir, results)

    spark.stop()

    # Model metrics (JSON-based, no Spark needed)
    _integrate_model_metrics(results)

    # -----------------------------------------------------------------------
    # Write integration manifest to MongoDB
    # -----------------------------------------------------------------------
    elapsed = time.time() - start
    results["execution_time_s"] = round(elapsed, 2)
    results["integrated_at"] = datetime.now().isoformat()
    results["pipeline_version"] = "phase10"

    _mongo_upsert_collection([results], "integration_log")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    total_docs = sum(v for k, v in results.items() if k.endswith("_docs"))
    print("\n" + "=" * 65)
    print("              PHASE 10 INTEGRATION -- SUMMARY")
    print("=" * 65)
    print(f"  {'Collection':<30} {'Documents':>10}")
    print("  " + "-" * 42)
    for key, val in results.items():
        if key.endswith("_docs"):
            label = key.replace("_docs", "").replace("_", " ").title()
            print(f"  {label:<30} {val:>10,}")
    print("  " + "-" * 42)
    print(f"  {'TOTAL':<30} {total_docs:>10,}")
    print(f"\n  Execution Time:  {elapsed:.2f}s")
    print("=" * 65)
    print("\n[+] Phase 10 complete. MongoDB is ready for the dashboard.\n")

    return results


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Phase 10 -- Integrate Spark analytics and ML results into MongoDB."
    )
    parser.add_argument(
        "--force-rerun",
        action="store_true",
        help="Force re-execution of all upstream Spark jobs before integration.",
    )
    args = parser.parse_args()
    run_integration(force_rerun=args.force_rerun)
