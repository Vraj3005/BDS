"""
Unit Test Suite for Phase 9: Threat Intelligence & IP Risk Scoring Engine
Distributed Cyber Threat Intelligence Platform
"""

import os
import sys
import unittest
from pathlib import Path

# Ensure worker processes use sys.executable
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, min as spark_min, max as spark_max


class TestPhase9RiskEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out_parquet = PATH_CONFIG["processed_data_dir"] / "ip_risk_scores.parquet"

        cls.spark = (
            SparkSession.builder.appName("TestPhase9RiskEngine")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.sql.shuffle.partitions", "2")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

        if not cls.out_parquet.exists():
            from ml.risk_engine.calculate_risk import compute_ip_risk_scores
            compute_ip_risk_scores(write_mongo=False)

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_risk_scores_parquet_exists(self):
        """Ensure ip_risk_scores.parquet exists and has records."""
        self.assertTrue(self.out_parquet.exists(), f"Missing file: {self.out_parquet}")
        df = self.spark.read.parquet(str(self.out_parquet))
        count = df.count()
        self.assertGreater(count, 0, "ip_risk_scores.parquet is empty")

    def test_risk_score_schema(self):
        """Verify expected columns and types exist in risk scores Parquet."""
        df = self.spark.read.parquet(str(self.out_parquet))
        expected_cols = {
            "source_ip",
            "total_flows",
            "attack_count",
            "unique_destinations",
            "risk_score",
            "risk_level",
            "recommended_action",
        }
        self.assertTrue(expected_cols.issubset(set(df.columns)))

    def test_risk_score_bounds(self):
        """Ensure all computed risk scores lie strictly between 0 and 100."""
        df = self.spark.read.parquet(str(self.out_parquet))
        min_max = df.select(
            spark_min("risk_score").alias("min_score"),
            spark_max("risk_score").alias("max_score"),
        ).collect()[0]

        self.assertGreaterEqual(min_max["min_score"], 0)
        self.assertLessEqual(min_max["max_score"], 100)

    def test_risk_level_categories(self):
        """Ensure risk tiers strictly adhere to valid categories."""
        df = self.spark.read.parquet(str(self.out_parquet))
        unique_levels = {
            row["risk_level"]
            for row in df.select("risk_level").distinct().collect()
        }
        allowed = {"Low", "Medium", "High", "Critical"}
        self.assertTrue(unique_levels.issubset(allowed))

    def test_risk_tier_threshold_consistency(self):
        """Validate that risk_level matches risk_score tier boundaries."""
        df = self.spark.read.parquet(str(self.out_parquet))

        # Check Critical >= 76
        critical_violations = df.filter(
            (col("risk_level") == "Critical") & (col("risk_score") < 76)
        ).count()
        self.assertEqual(critical_violations, 0)

        # Check High between 51 and 75
        high_violations = df.filter(
            (col("risk_level") == "High") & ((col("risk_score") < 51) | (col("risk_score") > 75))
        ).count()
        self.assertEqual(high_violations, 0)

        # Check Medium between 26 and 50
        med_violations = df.filter(
            (col("risk_level") == "Medium") & ((col("risk_score") < 26) | (col("risk_score") > 50))
        ).count()
        self.assertEqual(med_violations, 0)

        # Check Low < 26
        low_violations = df.filter(
            (col("risk_level") == "Low") & (col("risk_score") >= 26)
        ).count()
        self.assertEqual(low_violations, 0)

    def test_defense_action_mapping(self):
        """Verify recommended actions align with risk levels."""
        df = self.spark.read.parquet(str(self.out_parquet))
        critical_action = df.filter(col("risk_level") == "Critical").select("recommended_action").first()
        if critical_action:
            self.assertEqual(critical_action["recommended_action"], "Auto-Block & Quarantine")

        low_action = df.filter(col("risk_level") == "Low").select("recommended_action").first()
        if low_action:
            self.assertEqual(low_action["recommended_action"], "Standard Network Monitoring")


if __name__ == "__main__":
    unittest.main()
