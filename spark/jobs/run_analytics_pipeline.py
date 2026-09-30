"""
Phase 7 Analytics Orchestrator
Distributed Cyber Threat Intelligence Platform

Runs the full Phase 7 analytics pipeline in sequence:
  Step A: attack_statistics.py  — attack-type & protocol distribution
  Step B: ip_timeline_analysis.py (IP mode)      — source/dest IP frequency
  Step C: ip_timeline_analysis.py (timeline mode) — hourly/daily timeline

Usage (from project root):
    python spark/jobs/run_analytics_pipeline.py
"""

import os
import sys
import time
import json
from pathlib import Path

os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG


def run_analytics_pipeline():
    """Execute the full Phase 7 analytics pipeline and report results."""
    total_start = time.time()

    print("\n" + "=" * 65)
    print("        PHASE 7 — ANALYTICS PIPELINE ORCHESTRATOR")
    print("=" * 65)
    print(f"  Cleaned Parquet: {PATH_CONFIG['processed_data_dir'] / 'cleaned_logs.parquet'}")
    print(f"  Output Dir:      {PATH_CONFIG['processed_data_dir']}")
    print("=" * 65)

    all_results = {}

    # -------------------------------------------------------------------
    # Step A: Attack statistics & distribution
    # -------------------------------------------------------------------
    print("\n>>> STEP A: Attack Statistics & Distribution Aggregation")
    from spark.analytics.attack_statistics import run_attack_statistics
    stats_results = run_attack_statistics(write_mongo=True)
    all_results["attack_statistics"] = stats_results
    print(f"[✓] Step A complete — {stats_results.get('total_records_analysed', 0):,} records analysed.")

    # -------------------------------------------------------------------
    # Step B: IP threat frequency analysis
    # -------------------------------------------------------------------
    print("\n>>> STEP B: IP Threat Frequency Analysis")
    from spark.analytics.ip_timeline_analysis import run_ip_analysis
    ip_results = run_ip_analysis(write_mongo=True)
    all_results["ip_analysis"] = ip_results
    print(f"[✓] Step B complete — {ip_results.get('top_attacking_ips', 0)} top attacking IPs identified.")

    # -------------------------------------------------------------------
    # Step C: Network timeline analysis
    # -------------------------------------------------------------------
    print("\n>>> STEP C: Network Timeline Analysis")
    from spark.analytics.ip_timeline_analysis import run_timeline_analysis
    timeline_results = run_timeline_analysis(write_mongo=True)
    all_results["timeline_analysis"] = timeline_results
    print(f"[✓] Step C complete — {timeline_results.get('hourly_timeline_rows', 0)} hourly buckets generated.")

    # -------------------------------------------------------------------
    # Persist combined summary
    # -------------------------------------------------------------------
    elapsed = time.time() - total_start
    all_results["total_pipeline_time_s"] = round(elapsed, 2)

    summary_path = PATH_CONFIG["processed_data_dir"] / "phase7_analytics_summary.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2)

    print("\n" + "=" * 65)
    print("        PHASE 7 ANALYTICS PIPELINE — COMPLETED")
    print("=" * 65)
    print(f"  Total Pipeline Duration:   {elapsed:.2f}s")
    print(f"  Combined Summary:          {summary_path}")
    print("=" * 65)
    print("\n[+] Phase 7 complete. Analytics ready for Phase 8 (ML Training).\n")

    return all_results


if __name__ == "__main__":
    run_analytics_pipeline()
