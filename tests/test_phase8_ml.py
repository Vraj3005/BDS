"""
Unit Test Suite for Phase 8: Machine Learning Intrusion Classification
Distributed Cyber Threat Intelligence Platform
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

from config.settings import PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.ml.classification import RandomForestClassificationModel
from ml.prediction.predict_threat import determine_severity, load_label_mapping


class TestPhase8ML(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models_dir = PATH_CONFIG["models_dir"]
        cls.model_path = cls.models_dir / "rf_threat_model"
        cls.metrics_path = cls.models_dir / "model_metrics.json"
        cls.confusion_path = cls.models_dir / "confusion_matrix.json"
        cls.label_map_path = cls.models_dir / "label_mapping.json"

        cls.spark = (
            SparkSession.builder.appName("TestPhase8ML")
            .master(get_spark_master_url(use_cluster=False))
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.sql.shuffle.partitions", "2")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_model_artifact_exists(self):
        """Ensure serialized RandomForest model artifact exists and is loadable."""
        self.assertTrue(self.model_path.exists(), f"Missing model: {self.model_path}")
        model = RandomForestClassificationModel.load(str(self.model_path))
        self.assertIsNotNone(model)
        self.assertGreaterEqual(model.numClasses, 5)

    def test_label_mapping_file(self):
        """Ensure label_mapping.json exists and defines canonical attack types."""
        self.assertTrue(self.label_map_path.exists())
        mapping = load_label_mapping()
        self.assertEqual(len(mapping), 5)
        classes = set(mapping.values())
        expected = {"BENIGN", "DDoS", "PortScan", "Botnet", "BruteForce"}
        self.assertTrue(expected.issubset(classes))

    def test_model_metrics(self):
        """Ensure model metrics are computed and within valid ranges."""
        self.assertTrue(self.metrics_path.exists())
        with open(self.metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        self.assertIn("decision_tree", metrics)
        self.assertIn("random_forest", metrics)

        rf = metrics["random_forest"]
        self.assertGreaterEqual(rf["accuracy"], 0.40)
        self.assertLessEqual(rf["accuracy"], 1.0)
        self.assertGreaterEqual(rf["f1_score"], 0.40)

    def test_confusion_matrix(self):
        """Ensure confusion matrix exists and has non-zero entries."""
        self.assertTrue(self.confusion_path.exists())
        with open(self.confusion_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("confusion_matrix", data)
        self.assertIn("per_class_metrics", data)
        self.assertGreater(data["overall_accuracy"], 0.40)

    def test_severity_determination(self):
        """Test severity tier assignment based on attack type and confidence."""
        self.assertEqual(determine_severity("BENIGN", 95.0), "Low")
        self.assertEqual(determine_severity("DDoS", 85.0), "Critical")
        self.assertEqual(determine_severity("DDoS", 65.0), "High")
        self.assertEqual(determine_severity("PortScan", 80.0), "Medium")
        self.assertEqual(determine_severity("PortScan", 50.0), "Low")
        self.assertEqual(determine_severity("Botnet", 75.0), "High")


if __name__ == "__main__":
    unittest.main()
