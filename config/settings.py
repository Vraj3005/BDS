"""
Centralized settings and environment loader for the Distributed Cyber Threat Intelligence Platform.
Supports standalone local development, Dockerized containers, or 3-node cluster setups.
"""

import os
from pathlib import Path

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Attempt to load .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        load_dotenv(dotenv_path=env_file)
except ImportError:
    pass

# ==========================================
# MongoDB Configuration
# ==========================================
MONGO_CONFIG = {
    "host": os.getenv("MONGO_HOST", "localhost"),
    "port": int(os.getenv("MONGO_PORT", "27017")),
    "router_port": int(os.getenv("MONGO_ROUTER_PORT", "27017")),
    "shard1_port": int(os.getenv("MONGO_SHARD1_PORT", "27018")),
    "shard2_port": int(os.getenv("MONGO_SHARD2_PORT", "27019")),
    "db_name": os.getenv("MONGO_DB_NAME", "cyber_intel"),
    "collections": {
        "network_logs": os.getenv("MONGO_LOGS_COLLECTION", "network_logs"),
        "attack_stats": os.getenv("MONGO_ATTACK_STATS_COLLECTION", "attack_stats"),
        "ip_reputation": os.getenv("MONGO_IP_REPUTATION_COLLECTION", "ip_reputation"),
        "timeline_stats": os.getenv("MONGO_TIMELINE_COLLECTION", "timeline_stats"),
        "predictions": os.getenv("MONGO_PREDICTIONS_COLLECTION", "predictions"),
    }
}

def get_mongo_uri(custom_port: int = None) -> str:
    """Return MongoDB connection URI."""
    host = MONGO_CONFIG["host"]
    port = custom_port if custom_port else MONGO_CONFIG["port"]
    return f"mongodb://{host}:{port}"


# ==========================================
# Hadoop HDFS Configuration
# ==========================================
HDFS_CONFIG = {
    "namenode_host": os.getenv("HDFS_NAMENODE_HOST", "localhost"),
    "namenode_port": int(os.getenv("HDFS_NAMENODE_PORT", "9000")),
    "base_dir": os.getenv("HDFS_BASE_DIR", "/cybersecurity"),
}

def get_hdfs_url() -> str:
    """Return HDFS NameNode URL."""
    return f"hdfs://{HDFS_CONFIG['namenode_host']}:{HDFS_CONFIG['namenode_port']}"


# ==========================================
# Apache Spark Configuration
# ==========================================
SPARK_CONFIG = {
    "master_host": os.getenv("SPARK_MASTER_HOST", "localhost"),
    "master_port": int(os.getenv("SPARK_MASTER_PORT", "7077")),
    "app_name": os.getenv("SPARK_APP_NAME", "CyberThreatAnalytics"),
    "driver_memory": os.getenv("SPARK_DRIVER_MEMORY", "2g"),
    "executor_memory": os.getenv("SPARK_EXECUTOR_MEMORY", "2g"),
    "local_master": "local[*]",
}

def get_spark_master_url(use_cluster: bool = False) -> str:
    """Return Spark Master URL (local or cluster mode)."""
    if use_cluster:
        return f"spark://{SPARK_CONFIG['master_host']}:{SPARK_CONFIG['master_port']}"
    return SPARK_CONFIG["local_master"]


# ==========================================
# File System Paths
# ==========================================
PATH_CONFIG = {
    "base_dir": BASE_DIR,
    "data_dir": BASE_DIR / "data",
    "raw_data_dir": BASE_DIR / "data" / "raw",
    "processed_data_dir": BASE_DIR / "data" / "processed",
    "sample_csv": BASE_DIR / "data" / "raw" / "sample_cicids2017.csv",
    "models_dir": BASE_DIR / "ml" / "models",
    "reports_dir": BASE_DIR / "docs" / "reports",
}
