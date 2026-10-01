"""
PySpark Machine Learning Training Pipeline
Distributed Cyber Threat Intelligence Platform

Trains intrusion detection classifiers (Decision Tree & Random Forest):
1. Loads vectorized features from features.parquet.
2. Performs 80/20 stratified train/test split.
3. Trains DecisionTreeClassifier baseline.
4. Trains RandomForestClassifier ensemble model.
5. Evaluates models on Accuracy, F1-Score, Precision, and Recall.
6. Serializes the best performing model artifact to ml/models/rf_threat_model.
7. Saves performance benchmarks to ml/models/model_metrics.json.
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
from pyspark.ml.classification import DecisionTreeClassifier, RandomForestClassifier
from pyspark.ml.evaluation import MulticlassClassificationEvaluator


def get_spark_session(app_name="CyberThreat-ML-Training"):
    return (
        SparkSession.builder.appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def train_models(features_parquet: Path = None, models_dir: Path = None):
    input_path = features_parquet or (PATH_CONFIG["processed_data_dir"] / "features.parquet")
    out_models_dir = models_dir or PATH_CONFIG["models_dir"]

    # Ensure features exist
    if not input_path.exists():
        print(f"[*] Features dataset not found at {input_path}. Running feature engineering...")
        from spark.preprocessing.feature_engineering import build_features
        build_features()

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("      PYSPARK ML PIPELINE: THREAT CLASSIFIER TRAINING")
    print("=" * 65)
    print(f"Source Features:      {input_path}")
    print(f"Models Directory:     {out_models_dir}")

    start_time = time.time()

    # 1. Ingest Feature Vector Dataset
    print("\n[Step 1/5] Loading vectorized feature dataset...")
    data_df = spark.read.parquet(str(input_path))
    total_records = data_df.count()
    print(f"  [OK] Ingested {total_records:,} records with feature vectors.")

    # 2. Train / Test Split
    print("\n[Step 2/5] Performing 80/20 train/test split (seed=42)...")
    train_df, test_df = data_df.randomSplit([0.8, 0.2], seed=42)
    train_count = train_df.count()
    test_count = test_df.count()
    print(f"  [OK] Training Set:   {train_count:,} records ({train_count/total_records*100:.1f}%)")
    print(f"  [OK] Testing Set:    {test_count:,} records ({test_count/total_records*100:.1f}%)")

    # 3. Decision Tree Classifier
    print("\n[Step 3/5] Training Decision Tree Classifier (maxDepth=5)...")
    dt = DecisionTreeClassifier(
        labelCol="label",
        featuresCol="features",
        maxDepth=5,
        seed=42
    )
    dt_start = time.time()
    dt_model = dt.fit(train_df)
    dt_time = time.time() - dt_start
    dt_predictions = dt_model.transform(test_df)
    print(f"  [OK] Decision Tree trained in {dt_time:.2f}s.")

    # 4. Random Forest Classifier
    print("\n[Step 4/5] Training Random Forest Classifier (numTrees=20, maxDepth=7)...")
    rf = RandomForestClassifier(
        labelCol="label",
        featuresCol="features",
        numTrees=20,
        maxDepth=7,
        seed=42
    )
    rf_start = time.time()
    rf_model = rf.fit(train_df)
    rf_time = time.time() - rf_start
    rf_predictions = rf_model.transform(test_df)
    print(f"  [OK] Random Forest trained in {rf_time:.2f}s.")

    # 5. Model Evaluation
    print("\n[Step 5/5] Evaluating models on held-out test data...")
    eval_acc = MulticlassClassificationEvaluator(labelCol="label", predictionCol="prediction", metricName="accuracy")
    eval_f1 = MulticlassClassificationEvaluator(labelCol="label", predictionCol="prediction", metricName="f1")
    eval_prec = MulticlassClassificationEvaluator(labelCol="label", predictionCol="prediction", metricName="weightedPrecision")
    eval_rec = MulticlassClassificationEvaluator(labelCol="label", predictionCol="prediction", metricName="weightedRecall")

    metrics = {
        "decision_tree": {
            "accuracy": round(float(eval_acc.evaluate(dt_predictions)), 4),
            "f1_score": round(float(eval_f1.evaluate(dt_predictions)), 4),
            "precision": round(float(eval_prec.evaluate(dt_predictions)), 4),
            "recall": round(float(eval_rec.evaluate(dt_predictions)), 4),
            "training_time_s": round(dt_time, 2)
        },
        "random_forest": {
            "accuracy": round(float(eval_acc.evaluate(rf_predictions)), 4),
            "f1_score": round(float(eval_f1.evaluate(rf_predictions)), 4),
            "precision": round(float(eval_prec.evaluate(rf_predictions)), 4),
            "recall": round(float(eval_rec.evaluate(rf_predictions)), 4),
            "training_time_s": round(rf_time, 2)
        }
    }

    # Display Comparison Table
    print("=" * 65)
    print("                  MODEL EVALUATION BENCHMARKS")
    print("=" * 65)
    print(f"{'Metric':<18} | {'Decision Tree':<16} | {'Random Forest (Ensemble)':<16}")
    print("-" * 65)
    print(f"{'Accuracy':<18} | {metrics['decision_tree']['accuracy']*100:<15.2f}% | {metrics['random_forest']['accuracy']*100:<15.2f}%")
    print(f"{'Weighted F1':<18} | {metrics['decision_tree']['f1_score']:<16.4f} | {metrics['random_forest']['f1_score']:<16.4f}")
    print(f"{'Precision':<18} | {metrics['decision_tree']['precision']:<16.4f} | {metrics['random_forest']['precision']:<16.4f}")
    print(f"{'Recall':<18} | {metrics['decision_tree']['recall']:<16.4f} | {metrics['random_forest']['recall']:<16.4f}")
    print(f"{'Training Time':<18} | {metrics['decision_tree']['training_time_s']:<15.2f}s | {metrics['random_forest']['training_time_s']:<15.2f}s")
    print("=" * 65)

    # Save Best Model Artifact (Random Forest)
    out_models_dir.mkdir(parents=True, exist_ok=True)
    rf_model_path = out_models_dir / "rf_threat_model"
    print(f"\nPersisting trained Random Forest model artifact to {rf_model_path}...")
    rf_model.write().overwrite().save(str(rf_model_path))
    print("  [OK] Random Forest model serialized successfully.")

    # Save metrics JSON
    metrics_file = out_models_dir / "model_metrics.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"  [OK] Saved benchmark metrics to {metrics_file}")

    total_time = time.time() - start_time
    print(f"\n[+] Training Pipeline Completed in {total_time:.2f}s")

    spark.stop()
    return metrics


if __name__ == "__main__":
    train_models()
