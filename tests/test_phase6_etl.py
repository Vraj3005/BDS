"""
Phase 6 ETL Test Suite
Distributed Cyber Threat Intelligence Platform

Tests:
  - clean_network_logs() produces a non-empty Parquet file with the
    expected schema and no null source_ip / destination_ip values.
  - build_features() produces a non-empty Parquet with 'features' and
    'label' columns, and the label mapping JSON is saved.
"""

import sys
import unittest
from pathlib import Path

# Project root on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import os
os.environ["PYSPARK_PYTHON"]        = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

from config.settings import PATH_CONFIG


class TestCleanLogs(unittest.TestCase):
    """Validates the log-cleaning ETL step."""

    @classmethod
    def setUpClass(cls):
        """Run clean_network_logs once before all tests in this class."""
        from spark.preprocessing.clean_logs import clean_network_logs
        cls.cleaned_count = clean_network_logs()

        # Read the produced Parquet for schema / content checks
        from pyspark.sql import SparkSession
        from config.settings import get_spark_master_url
        spark = (
            SparkSession.builder
            .appName("Phase6-CleanTest")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        spark.sparkContext.setLogLevel("ERROR")
        cleaned_path = PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet"
        cls.df = spark.read.parquet(str(cleaned_path))
        cls.spark = spark

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_cleaned_parquet_exists(self):
        cleaned_path = PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet"
        self.assertTrue(cleaned_path.exists(), "cleaned_logs.parquet was not created.")

    def test_cleaned_record_count_positive(self):
        self.assertGreater(self.cleaned_count, 0,
                           "clean_network_logs() returned 0 records.")

    def test_required_columns_present(self):
        required = {
            "source_ip", "destination_ip", "protocol",
            "flow_duration", "packet_length", "total_bytes",
            "packet_count", "attack_type", "severity",
            "timestamp", "hour", "day_of_week",
        }
        actual = set(self.df.columns)
        missing = required - actual
        self.assertFalse(missing, f"Missing columns after cleaning: {missing}")

    def test_no_null_source_ip(self):
        null_count = self.df.filter(self.df.source_ip.isNull()).count()
        self.assertEqual(null_count, 0, "Null source_ip found after cleaning.")

    def test_no_null_destination_ip(self):
        null_count = self.df.filter(self.df.destination_ip.isNull()).count()
        self.assertEqual(null_count, 0, "Null destination_ip found after cleaning.")

    def test_no_negative_flow_duration(self):
        from pyspark.sql.functions import col
        neg_count = self.df.filter(col("flow_duration") < 0).count()
        self.assertEqual(neg_count, 0, "Negative flow_duration found after cleaning.")

    def test_protocol_is_uppercase(self):
        from pyspark.sql.functions import col
        non_upper = self.df.filter(
            col("protocol") != col("protocol")
        ).count()
        # Verify all protocol values are uppercase strings
        import pyspark.sql.functions as F
        lower_count = self.df.filter(
            F.upper(col("protocol")) != col("protocol")
        ).count()
        self.assertEqual(lower_count, 0, "Protocol column contains non-uppercase values.")

    def test_hour_range(self):
        from pyspark.sql.functions import col
        out_of_range = self.df.filter(
            (col("hour") < 0) | (col("hour") > 23)
        ).count()
        self.assertEqual(out_of_range, 0, "hour column has values outside 0-23.")

    def test_day_of_week_range(self):
        from pyspark.sql.functions import col
        out_of_range = self.df.filter(
            (col("day_of_week") < 1) | (col("day_of_week") > 7)
        ).count()
        self.assertEqual(out_of_range, 0, "day_of_week has values outside 1-7.")


class TestFeatureEngineering(unittest.TestCase):
    """Validates the feature-engineering vectorization step."""

    @classmethod
    def setUpClass(cls):
        """Run build_features once before all tests in this class."""
        from spark.preprocessing.feature_engineering import build_features
        cls.feature_count = build_features()

        from pyspark.sql import SparkSession
        from config.settings import get_spark_master_url
        spark = (
            SparkSession.builder
            .appName("Phase6-FeatureTest")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.ui.enabled", "false")
            .getOrCreate()
        )
        spark.sparkContext.setLogLevel("ERROR")
        feature_path = PATH_CONFIG["processed_data_dir"] / "features.parquet"
        cls.df = spark.read.parquet(str(feature_path))
        cls.spark = spark

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_features_parquet_exists(self):
        feature_path = PATH_CONFIG["processed_data_dir"] / "features.parquet"
        self.assertTrue(feature_path.exists(), "features.parquet was not created.")

    def test_feature_record_count_positive(self):
        self.assertGreater(self.feature_count, 0,
                           "build_features() returned 0 records.")

    def test_features_column_present(self):
        self.assertIn("features", self.df.columns,
                      "'features' vector column missing from output.")

    def test_label_column_present(self):
        self.assertIn("label", self.df.columns,
                      "'label' column missing from output.")

    def test_label_mapping_json_saved(self):
        label_file = PATH_CONFIG["models_dir"] / "label_mapping.json"
        self.assertTrue(label_file.exists(),
                        f"label_mapping.json not found at {label_file}.")

    def test_label_mapping_json_valid(self):
        import json
        label_file = PATH_CONFIG["models_dir"] / "label_mapping.json"
        with open(label_file, "r", encoding="utf-8") as fh:
            mapping = json.load(fh)
        self.assertIsInstance(mapping, dict, "label_mapping.json is not a dict.")
        self.assertGreater(len(mapping), 0, "label_mapping.json is empty.")

    def test_no_null_label(self):
        null_count = self.df.filter(self.df.label.isNull()).count()
        self.assertEqual(null_count, 0, "Null labels found in features dataset.")

    def test_required_output_columns(self):
        required = {"timestamp", "source_ip", "destination_ip",
                    "attack_type", "label", "raw_features", "features"}
        actual = set(self.df.columns)
        missing = required - actual
        self.assertFalse(missing, f"Missing columns in feature output: {missing}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
