"""
Phase 7 Analytics Test Suite
Distributed Cyber Threat Intelligence Platform

Tests:
  - run_attack_statistics() produces non-empty Parquet outputs for all
    four aggregation types and saves a summary JSON.
  - run_ip_analysis() produces top_attacking_ips and top_targeted_ips
    Parquet files with expected columns.
  - run_timeline_analysis() produces hourly, daily, and surge-window
    Parquet files with correct row ranges.
"""

import sys
import json
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import os
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

from config.settings import PATH_CONFIG


class TestAttackStatistics(unittest.TestCase):
    """Validates the attack statistics & distribution aggregation job."""

    @classmethod
    def setUpClass(cls):
        """Run attack statistics pipeline once for all tests in this class."""
        from spark.analytics.attack_statistics import run_attack_statistics
        cls.results = run_attack_statistics(write_mongo=False)
        cls.out_dir = PATH_CONFIG["processed_data_dir"]

        # Open a shared Spark session for Parquet validation
        from pyspark.sql import SparkSession
        from config.settings import get_spark_master_url
        cls.spark = (
            SparkSession.builder
            .appName("Phase7-AttackStatsTest")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    # --- Parquet existence -----------------------------------------------

    def test_attack_distribution_parquet_exists(self):
        p = self.out_dir / "attack_distribution.parquet"
        self.assertTrue(p.exists(), "attack_distribution.parquet not created.")

    def test_protocol_distribution_parquet_exists(self):
        p = self.out_dir / "protocol_distribution.parquet"
        self.assertTrue(p.exists(), "protocol_distribution.parquet not created.")

    def test_hourly_intensity_parquet_exists(self):
        p = self.out_dir / "hourly_attack_intensity.parquet"
        self.assertTrue(p.exists(), "hourly_attack_intensity.parquet not created.")

    def test_severity_distribution_parquet_exists(self):
        p = self.out_dir / "severity_distribution.parquet"
        self.assertTrue(p.exists(), "severity_distribution.parquet not created.")

    def test_summary_json_exists(self):
        p = self.out_dir / "attack_stats_summary.json"
        self.assertTrue(p.exists(), "attack_stats_summary.json not created.")

    # --- Row count assertions --------------------------------------------

    def test_attack_distribution_non_empty(self):
        self.assertGreater(
            self.results.get("attack_distribution_rows", 0), 0,
            "attack_distribution result is empty."
        )

    def test_protocol_distribution_non_empty(self):
        self.assertGreater(
            self.results.get("protocol_distribution_rows", 0), 0,
            "protocol_distribution result is empty."
        )

    def test_hourly_buckets_valid_range(self):
        """Should have at most 24 hourly buckets."""
        rows = self.results.get("hourly_intensity_rows", 0)
        self.assertGreater(rows, 0, "No hourly buckets produced.")
        self.assertLessEqual(rows, 24, "More than 24 hourly buckets returned.")

    def test_severity_levels_non_empty(self):
        self.assertGreater(
            self.results.get("severity_distribution_rows", 0), 0,
            "severity_distribution result is empty."
        )

    # --- Schema checks ---------------------------------------------------

    def test_attack_distribution_schema(self):
        df = self.spark.read.parquet(
            str(self.out_dir / "attack_distribution.parquet")
        )
        required = {"attack_type", "total_flows", "pct_share"}
        missing = required - set(df.columns)
        self.assertFalse(missing, f"Missing columns: {missing}")

    def test_pct_share_sums_to_100(self):
        """Percentage shares of attack types should sum to ~100 %."""
        df = self.spark.read.parquet(
            str(self.out_dir / "attack_distribution.parquet")
        )
        from pyspark.sql.functions import sum as spark_sum
        total_pct = df.agg(spark_sum("pct_share")).collect()[0][0] or 0
        self.assertAlmostEqual(total_pct, 100.0, delta=1.0,
                               msg=f"pct_share sum is {total_pct}, expected ~100.")

    def test_summary_json_valid(self):
        p = self.out_dir / "attack_stats_summary.json"
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("total_records_analysed", data)
        self.assertGreater(data["total_records_analysed"], 0)


class TestIPAnalysis(unittest.TestCase):
    """Validates the IP threat frequency analysis job."""

    @classmethod
    def setUpClass(cls):
        from spark.analytics.ip_timeline_analysis import run_ip_analysis
        cls.results = run_ip_analysis(write_mongo=False)
        cls.out_dir = PATH_CONFIG["processed_data_dir"]

        from pyspark.sql import SparkSession
        from config.settings import get_spark_master_url
        cls.spark = (
            SparkSession.builder
            .appName("Phase7-IPTest")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_top_attacking_ips_parquet_exists(self):
        p = self.out_dir / "top_attacking_ips.parquet"
        self.assertTrue(p.exists(), "top_attacking_ips.parquet not created.")

    def test_top_targeted_ips_parquet_exists(self):
        p = self.out_dir / "top_targeted_ips.parquet"
        self.assertTrue(p.exists(), "top_targeted_ips.parquet not created.")

    def test_ip_crosstab_parquet_exists(self):
        p = self.out_dir / "ip_attack_crosstab.parquet"
        self.assertTrue(p.exists(), "ip_attack_crosstab.parquet not created.")

    def test_top_attacking_ips_non_empty(self):
        self.assertGreater(
            self.results.get("top_attacking_ips", 0), 0,
            "top_attacking_ips result is empty."
        )

    def test_top_attacking_ips_schema(self):
        df = self.spark.read.parquet(
            str(self.out_dir / "top_attacking_ips.parquet")
        )
        required = {"source_ip", "attack_flow_count", "total_bytes_sent_mb"}
        missing = required - set(df.columns)
        self.assertFalse(missing, f"Missing columns: {missing}")

    def test_attack_flow_counts_positive(self):
        df = self.spark.read.parquet(
            str(self.out_dir / "top_attacking_ips.parquet")
        )
        from pyspark.sql.functions import col
        neg = df.filter(col("attack_flow_count") <= 0).count()
        self.assertEqual(neg, 0, "Non-positive attack_flow_count found.")


class TestTimelineAnalysis(unittest.TestCase):
    """Validates the network timeline analysis job."""

    @classmethod
    def setUpClass(cls):
        from spark.analytics.ip_timeline_analysis import run_timeline_analysis
        cls.results = run_timeline_analysis(write_mongo=False)
        cls.out_dir = PATH_CONFIG["processed_data_dir"]

        from pyspark.sql import SparkSession
        from config.settings import get_spark_master_url
        cls.spark = (
            SparkSession.builder
            .appName("Phase7-TimelineTest")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_hourly_timeline_parquet_exists(self):
        p = self.out_dir / "network_timeline_hourly.parquet"
        self.assertTrue(p.exists(), "network_timeline_hourly.parquet not created.")

    def test_daily_cadence_parquet_exists(self):
        p = self.out_dir / "network_timeline_daily.parquet"
        self.assertTrue(p.exists(), "network_timeline_daily.parquet not created.")

    def test_surge_windows_parquet_exists(self):
        p = self.out_dir / "attack_surge_windows.parquet"
        self.assertTrue(p.exists(), "attack_surge_windows.parquet not created.")

    def test_hourly_row_count(self):
        rows = self.results.get("hourly_timeline_rows", 0)
        self.assertGreater(rows, 0)
        self.assertLessEqual(rows, 24)

    def test_daily_cadence_row_count(self):
        rows = self.results.get("daily_cadence_rows", 0)
        self.assertGreater(rows, 0)
        self.assertLessEqual(rows, 7)

    def test_surge_windows_count(self):
        rows = self.results.get("surge_window_rows", 0)
        self.assertGreater(rows, 0, "Expected at least 1 surge window.")
        self.assertLessEqual(rows, 4, "Expected at most 4 six-hour surge windows.")

    def test_hourly_schema(self):
        df = self.spark.read.parquet(
            str(self.out_dir / "network_timeline_hourly.parquet")
        )
        required = {"hour", "total_flows", "attack_flows", "benign_flows", "attack_rate_pct"}
        missing = required - set(df.columns)
        self.assertFalse(missing, f"Missing columns: {missing}")

    def test_hour_values_in_range(self):
        from pyspark.sql.functions import col
        df = self.spark.read.parquet(
            str(self.out_dir / "network_timeline_hourly.parquet")
        )
        out_of_range = df.filter((col("hour") < 0) | (col("hour") > 23)).count()
        self.assertEqual(out_of_range, 0, "Hour values outside 0-23 found.")

    def test_attack_rate_pct_in_range(self):
        from pyspark.sql.functions import col
        df = self.spark.read.parquet(
            str(self.out_dir / "network_timeline_hourly.parquet")
        )
        out_of_range = df.filter(
            (col("attack_rate_pct") < 0) | (col("attack_rate_pct") > 100)
        ).count()
        self.assertEqual(out_of_range, 0, "attack_rate_pct outside [0, 100].")


if __name__ == "__main__":
    unittest.main(verbosity=2)
