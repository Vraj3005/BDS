"""
Spark Feature Engineering & Vectorization Pipeline
Distributed Cyber Threat Intelligence Platform

Transforms cleaned network logs into MLlib-ready feature vectors:
1. Categorical String Indexing for Protocol, Attack Type, and Severity.
2. Label metadata serialization for downstream ML inference.
3. Feature Vector Assembly across flow metrics and temporal signals.
4. Feature standardization using StandardScaler.
5. Exports vectorized ML dataset to Parquet.
"""

import os
import sys
import json
import time
from pathlib import Path

# Ensure consistent python runtime across driver and workers
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.ml import Pipeline
from pyspark.ml.feature import (
    StringIndexer, VectorAssembler, StandardScaler
)


def get_spark_session(app_name="CyberThreat-FeatureEngineering"):
    return (
        SparkSession.builder.appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def build_features(cleaned_parquet: Path = None, output_parquet: Path = None):
    input_path = cleaned_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")
    output_path = output_parquet or (PATH_CONFIG["processed_data_dir"] / "features.parquet")

    # If cleaned parquet doesn't exist, build it first
    if not input_path.exists():
        print(f"[*] Cleaned dataset not found. Running clean_logs.py first...")
        from spark.preprocessing.clean_logs import clean_network_logs
        clean_network_logs()

    spark = get_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 65)
    print("      SPARK FEATURE ENGINEERING & VECTORIZATION PIPELINE")
    print("=" * 65)
    print(f"Input Dataset:        {input_path}")
    print(f"Output ML Features:   {output_path}")

    start_time = time.time()

    # 1. Load cleaned Parquet data
    print("\n[Step 1/4] Reading cleaned log dataset...")
    df = spark.read.parquet(str(input_path))
    total_records = df.count()
    print(f"  [OK] Loaded {total_records:,} records.")

    # 2. String Indexing
    print("\n[Step 2/4] Indexing categorical variables (Protocol, Attack Type, Severity)...")
    protocol_indexer = StringIndexer(
        inputCol="protocol", outputCol="protocol_index", handleInvalid="keep"
    )
    severity_indexer = StringIndexer(
        inputCol="severity", outputCol="severity_index", handleInvalid="keep"
    )
    attack_indexer = StringIndexer(
        inputCol="attack_type", outputCol="label", handleInvalid="keep"
    )

    # 3. Vector Assembler
    print("\n[Step 3/4] Assembling feature vector...")
    feature_cols = [
        "flow_duration",
        "packet_length",
        "total_bytes",
        "packet_count",
        "hour",
        "day_of_week",
        "protocol_index",
        "severity_index"
    ]
    assembler = VectorAssembler(
        inputCols=feature_cols,
        outputCol="raw_features",
        handleInvalid="skip"
    )

    # 4. Standard Scaling
    scaler = StandardScaler(
        inputCol="raw_features",
        outputCol="features",
        withStd=True,
        withMean=False
    )

    # Assemble Pipeline
    pipeline = Pipeline(stages=[
        protocol_indexer,
        severity_indexer,
        attack_indexer,
        assembler,
        scaler
    ])

    print("\n[Step 4/4] Fitting transformations and scaling feature vectors...")
    pipeline_model = pipeline.fit(df)
    transformed_df = pipeline_model.transform(df)

    # Save Attack Label Mappings for ML inference & viva
    attack_labels = pipeline_model.stages[2].labels
    label_map = {int(idx): name for idx, name in enumerate(attack_labels)}
    label_file = PATH_CONFIG["models_dir"] / "label_mapping.json"
    label_file.parent.mkdir(parents=True, exist_ok=True)
    with open(label_file, "w", encoding="utf-8") as f:
        json.dump(label_map, f, indent=2)
    print(f"  [OK] Saved attack class label mapping to {label_file}")

    # Select columns for ML training & analytics
    final_df = transformed_df.select(
        "timestamp", "source_ip", "destination_ip", "attack_type",
        "label", "raw_features", "features"
    )

    # Export to Parquet
    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting vectorized features to {output_path}...")
    final_df.write.mode("overwrite").parquet(str(output_path))

    duration = time.time() - start_time

    print("=" * 65)
    print("                 FEATURE ENGINEERING SUMMARY")
    print("=" * 65)
    print(f"Total Vectorized Records: {final_df.count():,}")
    print(f"Feature Vector Dimension: {len(feature_cols)} dimensions")
    print(f"Feature Columns:          {', '.join(feature_cols)}")
    print(f"Target Label Classes:     {label_map}")
    print(f"Pipeline Duration:        {duration:.2f}s")
    print("=" * 65)

    print("\nSample Transformed ML Records:")
    final_df.select("source_ip", "attack_type", "label", "features").show(5, truncate=False)

    spark.stop()
    return final_df


if __name__ == "__main__":
    build_features()
