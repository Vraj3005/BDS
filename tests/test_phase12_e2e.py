"""
End-to-End Integration and System Validation Test Suite -- Phase 12
Distributed Cyber Threat Intelligence and Intrusion Analytics Platform

Validates the complete end-to-end distributed system across all phases:
1. Foundation & Configuration: Spark, Hadoop, MongoDB environment configs.
2. Ingestion & Raw Data: Raw CSV and initial schema integrity.
3. Spark Distributed ETL: Cleaned Parquet, schema fields, record counts.
4. Feature Engineering: Scaled vectors, categorical indexing, feature dimensions.
5. Distributed Analytics: Attack stats, protocol, severity, timeline, top IPs.
6. Machine Learning: RandomForest model artifact, label map, accuracy metrics.
7. Threat Intelligence: IP risk scores bounded in [0, 100], risk tiers, defense actions.
8. Dashboard Integration: Parquet and analytical tables ready for visualization.
"""

import os
import sys
import json
import unittest
from pathlib import Path

# Ensure worker processes use sys.executable
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, MONGO_CONFIG, SPARK_CONFIG, HDFS_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, min as spark_min, max as spark_max


class TestPhase12EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = PATH_CONFIG["processed_data_dir"]
        cls.raw_csv = PATH_CONFIG["raw_data_dir"] / "sample_cicids2017.csv"
        cls.models_dir = PATH_CONFIG["models_dir"]

        cls.spark = (
            SparkSession.builder.appName("TestPhase12-E2E")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.sql.shuffle.partitions", "2")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    # -----------------------------------------------------------------------
    # 1. Cluster & Environment Configuration Integrity
    # -----------------------------------------------------------------------
    def test_01_cluster_configurations(self):
        """Validate Spark, Hadoop, and MongoDB cluster configuration artifacts exist."""
        # Spark config
        spark_conf = base_dir / "spark" / "config"
        self.assertTrue((spark_conf / "spark-env.sh").exists(), "Missing spark-env.sh")
        self.assertTrue((spark_conf / "spark-defaults.conf").exists(), "Missing spark-defaults.conf")
        self.assertTrue((spark_conf / "workers").exists(), "Missing workers file")
        self.assertTrue((spark_conf / "docker-compose-spark.yml").exists(), "Missing docker-compose-spark.yml")

        # Hadoop config
        hadoop_conf = base_dir / "hadoop" / "config"
        self.assertTrue((hadoop_conf / "core-site.xml").exists(), "Missing core-site.xml")
        self.assertTrue((hadoop_conf / "hdfs-site.xml").exists(), "Missing hdfs-site.xml")

        # MongoDB config
        mongo_conf = base_dir / "mongodb" / "config"
        self.assertTrue((mongo_conf / "docker-compose-sharding.yml").exists(), "Missing docker-compose-sharding.yml")
        self.assertTrue((mongo_conf / "mongos.conf").exists(), "Missing mongos.conf")

    # -----------------------------------------------------------------------
    # 2. Raw Ingestion & Schema Integrity
    # -----------------------------------------------------------------------
    def test_02_raw_ingestion_dataset(self):
        """Validate raw CICIDS2017 dataset is present and contains required records."""
        self.assertTrue(self.raw_csv.exists(), f"Missing raw CSV: {self.raw_csv}")
        with open(self.raw_csv, "r", encoding="utf-8") as f:
            header = f.readline().strip().split(",")
            line_count = sum(1 for _ in f)

        expected_cols = {"timestamp", "source_ip", "destination_ip", "protocol", "attack_type"}
        self.assertTrue(expected_cols.issubset(set(header)))
        self.assertGreaterEqual(line_count, 1000, "Raw dataset contains fewer than 1000 records")

    # -----------------------------------------------------------------------
    # 3. Distributed Spark ETL Pipeline Output
    # -----------------------------------------------------------------------
    def test_03_spark_cleaned_logs(self):
        """Validate cleaned_logs.parquet schema, cleanliness, and non-empty record count."""
        cleaned_parquet = self.data_dir / "cleaned_logs.parquet"
        self.assertTrue(cleaned_parquet.exists(), f"Missing: {cleaned_parquet}")

        df = self.spark.read.parquet(str(cleaned_parquet))
        count = df.count()
        self.assertGreater(count, 0, "cleaned_logs.parquet is empty")

        # Verify key engineered / cleaned columns
        expected_cols = {
            "source_ip", "destination_ip", "protocol",
            "flow_duration", "packet_length", "total_bytes",
            "packet_count", "attack_type", "severity",
            "timestamp", "hour", "day_of_week"
        }
        self.assertTrue(expected_cols.issubset(set(df.columns)))

        # Verify no negative durations
        negative_durations = df.filter(col("flow_duration") < 0).count()
        self.assertEqual(negative_durations, 0, "Found invalid negative flow durations")

    # -----------------------------------------------------------------------
    # 4. Feature Engineering & Vectorization
    # -----------------------------------------------------------------------
    def test_04_feature_engineering_dataset(self):
        """Validate features.parquet contains scaled ML feature vectors and valid labels."""
        features_parquet = self.data_dir / "features.parquet"
        self.assertTrue(features_parquet.exists(), f"Missing: {features_parquet}")

        df = self.spark.read.parquet(str(features_parquet))
        self.assertIn("features", df.columns)
        self.assertIn("label", df.columns)
        self.assertIn("attack_type", df.columns)

        # Check vector size on first record
        first_row = df.select("features").first()
        vec_size = len(first_row["features"])
        self.assertGreaterEqual(vec_size, 4, "Vector size should have at least 4 dimensions")

    # -----------------------------------------------------------------------
    # 5. Distributed Analytics Aggregations
    # -----------------------------------------------------------------------
    def test_05_analytics_aggregations(self):
        """Verify all Phase 7 distributed analytical aggregations are produced and valid."""
        required_aggregations = [
            "attack_distribution.parquet",
            "protocol_distribution.parquet",
            "hourly_attack_intensity.parquet",
            "severity_distribution.parquet",
            "top_attacking_ips.parquet",
            "top_targeted_ips.parquet",
            "network_timeline_hourly.parquet",
        ]
        for agg_file in required_aggregations:
            path = self.data_dir / agg_file
            self.assertTrue(path.exists(), f"Missing analytics aggregation: {agg_file}")
            df = self.spark.read.parquet(str(path))
            self.assertGreater(df.count(), 0, f"Analytics table {agg_file} is empty")

    # -----------------------------------------------------------------------
    # 6. Machine Learning Model Artifacts & Benchmarks
    # -----------------------------------------------------------------------
    def test_06_machine_learning_pipeline(self):
        """Validate serialized ML model artifact, label mapping, and metrics."""
        rf_model_dir = self.models_dir / "rf_threat_model"
        label_file = self.models_dir / "label_mapping.json"
        metrics_file = self.models_dir / "model_metrics.json"

        self.assertTrue(rf_model_dir.exists(), "Missing rf_threat_model directory")
        self.assertTrue(label_file.exists(), "Missing label_mapping.json")
        self.assertTrue(metrics_file.exists(), "Missing model_metrics.json")

        with open(metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        self.assertIn("random_forest", metrics)
        rf_acc = metrics["random_forest"]["accuracy"]
        self.assertGreaterEqual(rf_acc, 0.40, f"Accuracy {rf_acc} is suspiciously low")
        self.assertLessEqual(rf_acc, 1.0)

    # -----------------------------------------------------------------------
    # 7. Threat Intelligence & IP Risk Scoring Engine
    # -----------------------------------------------------------------------
    def test_07_ip_risk_engine(self):
        """Validate 0-100 IP Risk Scoring distribution and threat tier boundaries."""
        risk_parquet = self.data_dir / "ip_risk_scores.parquet"
        self.assertTrue(risk_parquet.exists(), f"Missing: {risk_parquet}")

        df = self.spark.read.parquet(str(risk_parquet))
        stats = df.select(
            spark_min("risk_score").alias("min_score"),
            spark_max("risk_score").alias("max_score")
        ).first()

        self.assertGreaterEqual(stats["min_score"], 0)
        self.assertLessEqual(stats["max_score"], 100)

        # Ensure all records have valid risk tiers and defense policies
        valid_tiers = {"Low", "Medium", "High", "Critical"}
        distinct_tiers = {row["risk_level"] for row in df.select("risk_level").distinct().collect()}
        self.assertTrue(distinct_tiers.issubset(valid_tiers))

    # -----------------------------------------------------------------------
    # 8. Dashboard Data Readiness
    # -----------------------------------------------------------------------
    def test_08_dashboard_readiness(self):
        """Verify dashboard module exists and required analytical tables can be read."""
        app_file = base_dir / "dashboard" / "app.py"
        cluster_health_file = base_dir / "dashboard" / "cluster_health.py"

        self.assertTrue(app_file.exists(), "Missing dashboard/app.py")
        self.assertTrue(cluster_health_file.exists(), "Missing dashboard/cluster_health.py")

        # Verify Parquet tables can be read via Spark
        df_attack = self.spark.read.parquet(str(self.data_dir / "attack_distribution.parquet"))
        self.assertGreater(df_attack.count(), 0)
        self.assertIn("attack_type", df_attack.columns)


if __name__ == "__main__":
    unittest.main()
