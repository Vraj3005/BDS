"""
ETL Orchestrator - Phase 6
Distributed Cyber Threat Intelligence Platform

Runs the complete Phase 6 ETL pipeline in sequence:
  Step A: clean_logs.py   - raw CSV -> cleaned Parquet
  Step B: feature_engineering.py - cleaned Parquet -> ML feature Parquet

Usage (from project root):
    python spark/jobs/run_etl_pipeline.py
"""

import os
import sys
import time
from pathlib import Path

# Ensure consistent python runtime across driver and workers
os.environ["PYSPARK_PYTHON"]        = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG
from spark.preprocessing.clean_logs import clean_network_logs
from spark.preprocessing.feature_engineering import build_features


def run_etl_pipeline():
    """Execute the full Phase 6 ETL pipeline and report results."""
    total_start = time.time()

    print("\n" + "=" * 65)
    print("         PHASE 6 - SPARK ETL PIPELINE ORCHESTRATOR")
    print("=" * 65)
    print(f"  Raw Input:  {PATH_CONFIG['sample_csv']}")
    print(f"  Cleaned:    {PATH_CONFIG['processed_data_dir'] / 'cleaned_logs.parquet'}")
    print(f"  Features:   {PATH_CONFIG['processed_data_dir'] / 'features.parquet'}")
    print("=" * 65)

    # ---------------------------------------------------------------
    # Phase 6-A: Log Cleansing
    # ---------------------------------------------------------------
    print("\n>>> STEP A: Log Cleansing & Deduplication")
    cleaned_count = clean_network_logs()

    # ---------------------------------------------------------------
    # Phase 6-B: Feature Engineering
    # ---------------------------------------------------------------
    print("\n>>> STEP B: Feature Engineering & Vectorization")
    feature_count = build_features()

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    elapsed = time.time() - total_start
    print("\n" + "=" * 65)
    print("         PHASE 6 ETL PIPELINE - COMPLETED")
    print("=" * 65)
    print(f"  Cleaned Records Written:   {cleaned_count:,}")
    print(f"  Feature Records Written:   {feature_count:,}")
    print(f"  Total Pipeline Duration:   {elapsed:.2f}s")
    print("=" * 65)
    print("\n[+] Phase 6 complete. Outputs ready for Phase 7 (Analytics).\n")


if __name__ == "__main__":
    run_etl_pipeline()
