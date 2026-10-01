"""
PySpark Model Evaluation & Confusion Matrix
Distributed Cyber Threat Intelligence Platform

Generates multi-class confusion matrix and per-class performance metrics:
1. Loads the serialized RandomForest model and test features.
2. Computes the Confusion Matrix across all 5 classes (BENIGN, DDoS, PortScan, Botnet, BruteForce).
3. Computes per-class True Positives, False Positives, False Negatives.
4. Calculates per-class Precision, Recall, and F1-score.
5. Saves evaluation metrics to ml/models/confusion_matrix.json.
"""

import os
import sys
import json
import time
from pathlib import Path

# Ensure worker processes use sys.executable
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.mllib.evaluation import MulticlassMetrics


def get_spark_session(app_name="CyberThreat-ModelEvaluation"):
    return (
        SparkSession.builder.appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def evaluate_model(model_dir: Path = None, features_parquet: Path = None):
    rf_path = model_dir or (PATH_CONFIG["models_dir"] / "rf_threat_model")
    features_path = features_parquet or (PATH_CONFIG["processed_data_dir"] / "features.parquet")
    label_map_file = PATH_CONFIG["models_dir"] / "label_mapping.json"

    if not rf_path.exists():
        print(f"[-] Model not found at {rf_path}. Running train_models.py first...")
        from ml.training.train_models import train_models
        train_models()

    # Load label mapping
    if label_map_file.exists():
        with open(label_map_file, "r", encoding="utf-8") as f:
            label_map = {int(k): v for k, v in json.load(f).items()}
    else:
        label_map = {0: "PortScan", 1: "DDoS", 2: "BENIGN", 3: "BruteForce", 4: "Botnet"}

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("      PYSPARK ML EVALUATION: MULTI-CLASS CONFUSION MATRIX")
    print("=" * 65)

    # 1. Load Model and Features
    print(f"Loading trained Random Forest model from {rf_path}...")
    model = RandomForestClassificationModel.load(str(rf_path))

    print(f"Loading feature dataset from {features_path}...")
    data_df = spark.read.parquet(str(features_path))

    # Evaluate on the held-out test split (20%)
    _, test_df = data_df.randomSplit([0.8, 0.2], seed=42)
    test_count = test_df.count()
    print(f"  [OK] Evaluating on {test_count:,} test flow events.")

    # 2. Generate Predictions
    predictions = model.transform(test_df)

    # 3. Compute Confusion Matrix via MulticlassMetrics
    pred_and_label_rdd = predictions.select("prediction", "label").rdd.map(
        lambda row: (float(row.prediction), float(row.label))
    )
    metrics = MulticlassMetrics(pred_and_label_rdd)

    confusion_matrix = metrics.confusionMatrix().toArray().tolist()

    # Display Confusion Matrix Table
    print("\n" + "=" * 65)
    print("                 CONFUSION MATRIX TABLE")
    print("=" * 65)
    labels_sorted = sorted(label_map.keys())
    col_title = "Actual \\ Predicted"
    header = f"{col_title:<20} | " + " | ".join([f"{label_map[i]:<10}" for i in labels_sorted])
    print(header)
    print("-" * len(header))

    matrix_dict = {}
    for i in labels_sorted:
        actual_name = label_map.get(i, f"Class_{i}")
        row_vals = confusion_matrix[i] if i < len(confusion_matrix) else [0] * len(labels_sorted)
        row_str = f"{actual_name:<20} | " + " | ".join([f"{int(val):<10}" for val in row_vals])
        print(row_str)
        matrix_dict[actual_name] = {label_map.get(j, f"Class_{j}"): int(row_vals[j]) for j in labels_sorted if j < len(row_vals)}

    # 4. Per-Class Precision & Recall
    print("\n" + "=" * 65)
    print("               PER-CLASS CLASSIFICATION REPORT")
    print("=" * 65)
    print(f"{'Attack Class':<18} | {'Precision':<12} | {'Recall':<12} | {'F1-Score':<12}")
    print("-" * 65)

    per_class_metrics = {}
    for i in labels_sorted:
        c_name = label_map.get(i, f"Class_{i}")
        try:
            prec = round(metrics.precision(float(i)), 4)
            rec = round(metrics.recall(float(i)), 4)
            f1 = round(metrics.fMeasure(float(i), 1.0), 4)
        except Exception:
            prec, rec, f1 = 0.0, 0.0, 0.0

        per_class_metrics[c_name] = {"precision": prec, "recall": rec, "f1_score": f1}
        print(f"{c_name:<18} | {prec:<12.4f} | {rec:<12.4f} | {f1:<12.4f}")

    print("=" * 65)
    overall_acc = round(metrics.accuracy, 4)
    weighted_f1 = round(metrics.weightedFMeasure(), 4)
    print(f"Overall Accuracy:     {overall_acc * 100:.2f}%")
    print(f"Weighted F1-Measure:  {weighted_f1:.4f}")
    print("=" * 65)

    # Save to JSON
    result_data = {
        "overall_accuracy": overall_acc,
        "weighted_f1": weighted_f1,
        "confusion_matrix": matrix_dict,
        "per_class_metrics": per_class_metrics
    }
    out_json = PATH_CONFIG["models_dir"] / "confusion_matrix.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=2)
    print(f"[+] Saved evaluation and confusion matrix to {out_json}")

    spark.stop()
    return result_data


if __name__ == "__main__":
    evaluate_model()
