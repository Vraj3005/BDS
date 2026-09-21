"""
Foundation Unit Test Suite
Validates that the project directory scaffold, essential files,
and configuration modules are correctly initialized.
"""

import os
import unittest
from pathlib import Path

# Add project root to sys.path
import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import (
    MONGO_CONFIG,
    HDFS_CONFIG,
    SPARK_CONFIG,
    PATH_CONFIG,
    get_mongo_uri,
    get_hdfs_url,
    get_spark_master_url,
)


class TestProjectFoundation(unittest.TestCase):
    """Verifies that all foundational folders, files, and settings exist."""

    def test_essential_files_exist(self):
        """Ensure gitignore, requirements, and README exist."""
        expected_files = [
            BASE_DIR / ".gitignore",
            BASE_DIR / "requirements.txt",
            BASE_DIR / "README.md",
            BASE_DIR / ".env.example",
            BASE_DIR / "config" / "settings.py",
        ]
        for file_path in expected_files:
            self.assertTrue(file_path.exists(), f"Missing essential file: {file_path}")

    def test_directory_scaffold_exists(self):
        """Ensure all modular architecture directories are present."""
        expected_dirs = [
            BASE_DIR / "data",
            BASE_DIR / "data" / "raw",
            BASE_DIR / "data" / "processed",
            BASE_DIR / "config",
            BASE_DIR / "mongodb",
            BASE_DIR / "mongodb" / "config",
            BASE_DIR / "mongodb" / "scripts",
            BASE_DIR / "hadoop",
            BASE_DIR / "hadoop" / "config",
            BASE_DIR / "hadoop" / "scripts",
            BASE_DIR / "spark",
            BASE_DIR / "spark" / "jobs",
            BASE_DIR / "spark" / "preprocessing",
            BASE_DIR / "spark" / "analytics",
            BASE_DIR / "ml",
            BASE_DIR / "ml" / "training",
            BASE_DIR / "ml" / "models",
            BASE_DIR / "ml" / "prediction",
            BASE_DIR / "ml" / "risk_engine",
            BASE_DIR / "ingestion",
            BASE_DIR / "dashboard",
            BASE_DIR / "docs",
            BASE_DIR / "tests",
        ]
        for dir_path in expected_dirs:
            self.assertTrue(dir_path.is_dir(), f"Missing directory: {dir_path}")

    def test_settings_defaults(self):
        """Verify that default settings produce valid connection strings and paths."""
        mongo_uri = get_mongo_uri()
        self.assertTrue(mongo_uri.startswith("mongodb://") or mongo_uri.startswith("mongodb+srv://"))
        self.assertIn("cyber_intel", MONGO_CONFIG["db_name"])

        hdfs_url = get_hdfs_url()
        self.assertTrue(hdfs_url.startswith("hdfs://"))

        spark_url = get_spark_master_url()
        self.assertEqual(spark_url, "local[*]")

        self.assertEqual(PATH_CONFIG["base_dir"], BASE_DIR)


if __name__ == "__main__":
    unittest.main()
