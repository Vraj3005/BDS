"""
PySpark Cyber Threat Intrusion Predictor
Distributed Cyber Threat Intelligence Platform

Performs batch and single-event intrusion inference using trained Random Forest model:
1. Loads serialized RandomForest model from ml/models/rf_threat_model.
2. Loads attack class mapping from ml/models/label_mapping.json.
3. Computes predicted attack label and exact confidence percentage from class probabilities.
4. Generates formatted threat intelligence alerts with severity tiers.
5. Optionally streams prediction events into MongoDB collection 'predictions'.
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Ensure worker processes use sys.executable
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, MONGO_CONFIG, get_spark_master_url, get_mongo_client
from pyspark.sql import SparkSession
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.sql.functions import col, udf
from pyspark.sql.types import StringType, DoubleType, StructType, StructField


def get_spark_session(app_name="CyberThreat-Predictor"):
    return (
        SparkSession.builder.appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def load_label_mapping():
    label_file = PATH_CONFIG["models_dir"] / "label_mapping.json"
    if label_file.exists():
        with open(label_file, "r", encoding="utf-8") as f:
            return {int(k): v for k, v in json.load(f).items()}
    return {0: "PortScan", 1: "DDoS", 2: "BENIGN", 3: "BruteForce", 4: "Botnet"}


def determine_severity(attack_type: str, confidence: float) -> str:
    if attack_type == "BENIGN":
        return "Low"
    elif attack_type == "PortScan":
        return "Medium" if confidence > 75.0 else "Low"
    elif attack_type in ["Botnet", "BruteForce"]:
        return "High" if confidence > 70.0 else "Medium"
    else:  # DDoS
        return "Critical" if confidence > 80.0 else "High"


def predict_batch(limit: int = 10, write_mongo: bool = False):
    model_path = PATH_CONFIG["models_dir"] / "rf_threat_model"
    features_path = PATH_CONFIG["processed_data_dir"] / "features.parquet"

    if not model_path.exists():
        print(f"[-] Model not found at {model_path}. Running train_models.py first...")
        from ml.training.train_models import train_models
        train_models()

    label_map = load_label_mapping()
    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("      DISTRIBUTED CYBER THREAT INTRUSION PREDICTOR")
    print("=" * 65)

    print(f"Loading trained Random Forest model from {model_path}...")
    model = RandomForestClassificationModel.load(str(model_path))

    print(f"Loading feature records from {features_path}...")
    df = spark.read.parquet(str(features_path))

    # Run inference
    predictions = model.transform(df)

    # Collect sample rows for display and potential MongoDB persistence
    sample_rows = predictions.select(
        "timestamp", "source_ip", "destination_ip", "attack_type", "prediction", "probability"
    ).limit(limit).collect()

    print("\n" + "=" * 65)
    print(f"          INTRUSION PREDICTION RESULTS (SAMPLE {len(sample_rows)} EVENTS)")
    print("=" * 65)

    mongo_records = []
    for idx, row in enumerate(sample_rows, 1):
        pred_label_idx = int(row.prediction)
        pred_attack = label_map.get(pred_label_idx, f"Unknown_{pred_label_idx}")
        actual_attack = row.attack_type

        # Calculate exact confidence from probability vector
        prob_vector = row.probability.toArray()
        confidence = round(float(prob_vector[pred_label_idx]) * 100, 2)
        severity = determine_severity(pred_attack, confidence)

        timestamp_str = str(row.timestamp) if row.timestamp else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"Event #{idx:02d}: {row.source_ip} -> {row.destination_ip}")
        print(f"  Timestamp:        {timestamp_str}")
        print(f"  Actual Attack:    {actual_attack}")
        print(f"  Predicted Attack: {pred_attack}")
        print(f"  Model Confidence: {confidence:.2f}%")
        print(f"  Threat Severity:  {severity}")
        print("-" * 65)

        if write_mongo:
            mongo_records.append({
                "timestamp": timestamp_str,
                "source_ip": row.source_ip,
                "destination_ip": row.destination_ip,
                "actual_attack": actual_attack,
                "predicted_attack": pred_attack,
                "confidence": confidence,
                "severity": severity,
                "analyzed_at": datetime.now().isoformat()
            })

    if write_mongo and mongo_records:
        try:
            client = get_mongo_client()
            db = client[MONGO_CONFIG["db_name"]]
            col_name = MONGO_CONFIG["collections"]["predictions"]
            db[col_name].insert_many(mongo_records)
            print(f"[+] Successfully saved {len(mongo_records)} predictions to MongoDB '{col_name}'.")
            client.close()
        except Exception as e:
            print(f"[-] MongoDB export note: {e}")

    print("=" * 65)
    print(f"[OK] Completed inference on {len(sample_rows)} network flows.")
    print("=" * 65)

    spark.stop()
    return sample_rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predict cyber threat intrusions using trained ML model.")
    parser.add_argument("--limit", type=int, default=5, help="Number of records to predict and display")
    parser.add_argument("--mongo", action="store_true", help="Store predictions into MongoDB Atlas")
    args = parser.parse_args()

    predict_batch(limit=args.limit, write_mongo=args.mongo)
