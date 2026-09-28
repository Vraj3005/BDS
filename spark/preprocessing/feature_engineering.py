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
sys.path.insert(0, str(base_dir))

from config.settings import PATH_CONFIG, get_spark_master_url
from pyspark.sql import SparkSession
from pyspark.ml import Pipeline
from pyspark.ml.feature import StringIndexer, VectorAssembler, StandardScaler


def get_spark_session(app_name="CyberThreat-FeatureEngineering"):
    """Build and return a local SparkSession."""
    return (
        SparkSession.builder
        .appName(app_name)
        .master(get_spark_master_url(use_cluster=False))
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )


def build_features(cleaned_parquet: Path = None, output_parquet: Path = None):
    """
    Build ML feature vectors from cleaned Parquet data.

    If the cleaned parquet does not yet exist, the cleaning pipeline is
    automatically invoked first.

    Args:
        cleaned_parquet: Path to the cleaned Parquet produced by clean_logs.py.
        output_parquet:  Destination Parquet path for the feature dataset.

    Returns:
        Count of vectorized records written.
    """
    input_path  = cleaned_parquet or (PATH_CONFIG["processed_data_dir"] / "cleaned_logs.parquet")
    output_path = output_parquet  or (PATH_CONFIG["processed_data_dir"] / "features.parquet")

    # Auto-run cleaning step if parquet is missing
    if not Path(input_path).exists():
        print("[*] Cleaned dataset not found - running clean_logs pipeline first...")
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

    # -------------------------------------------------------------------
    # Step 1: Load cleaned Parquet data
    # -------------------------------------------------------------------
    print("\n[Step 1/4] Reading cleaned log dataset...")
    df = spark.read.parquet(str(input_path))
    total_records = df.count()
    print(f"  [OK] Loaded {total_records:,} records.")

    # -------------------------------------------------------------------
    # Step 2: String indexing of categorical columns
    # -------------------------------------------------------------------
    print("\n[Step 2/4] Indexing categorical variables (Protocol, Severity, Attack Type)...")
    protocol_indexer = StringIndexer(
        inputCol="protocol",    outputCol="protocol_index", handleInvalid="keep"
    )
    severity_indexer = StringIndexer(
        inputCol="severity",    outputCol="severity_index", handleInvalid="keep"
    )
    attack_indexer = StringIndexer(
        inputCol="attack_type", outputCol="label",          handleInvalid="keep"
    )

    # -------------------------------------------------------------------
    # Step 3: Assemble raw feature vector
    # -------------------------------------------------------------------
    print("\n[Step 3/4] Assembling feature vector...")
    feature_cols = [
        "flow_duration",
        "packet_length",
        "total_bytes",
        "packet_count",
        "hour",
        "day_of_week",
        "protocol_index",
        "severity_index",
    ]
    assembler = VectorAssembler(
        inputCols=feature_cols,
        outputCol="raw_features",
        handleInvalid="skip"
    )

    # -------------------------------------------------------------------
    # Step 4: Scale features (std-normalise, no mean-centering for sparse compat)
    # -------------------------------------------------------------------
    scaler = StandardScaler(
        inputCol="raw_features",
        outputCol="features",
        withStd=True,
        withMean=False
    )

    # -------------------------------------------------------------------
    # Fit pipeline
    # -------------------------------------------------------------------
    pipeline = Pipeline(stages=[
        protocol_indexer,
        severity_indexer,
        attack_indexer,
        assembler,
        scaler,
    ])

    print("\n[Step 4/4] Fitting transformations and scaling feature vectors...")
    pipeline_model  = pipeline.fit(df)
    transformed_df  = pipeline_model.transform(df)

    # -------------------------------------------------------------------
    # Persist attack-label -> class-name mapping for ML inference
    # -------------------------------------------------------------------
    attack_labels = pipeline_model.stages[2].labels   # attack_indexer is index 2
    label_map     = {int(i): name for i, name in enumerate(attack_labels)}
    label_file    = PATH_CONFIG["models_dir"] / "label_mapping.json"
    label_file.parent.mkdir(parents=True, exist_ok=True)
    with open(label_file, "w", encoding="utf-8") as fh:
        json.dump(label_map, fh, indent=2)
    print(f"  [OK] Attack label map ({len(label_map)} classes) saved -> {label_file}")

    # -------------------------------------------------------------------
    # Select final columns and write Parquet
    # -------------------------------------------------------------------
    final_df = transformed_df.select(
        "timestamp", "source_ip", "destination_ip",
        "attack_type", "label", "raw_features", "features"
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting vectorized features -> {output_path} ...")
    final_df.write.mode("overwrite").parquet(str(output_path))

    final_count = final_df.count()
    duration    = time.time() - start_time

    print("=" * 65)
    print("                 FEATURE ENGINEERING SUMMARY")
    print("=" * 65)
    print(f"  Vectorized Records:        {final_count:,}")
    print(f"  Feature Vector Dimensions: {len(feature_cols)}")
    print(f"  Feature Columns:           {', '.join(feature_cols)}")
    print(f"  Attack Classes:            {label_map}")
    print(f"  Pipeline Duration:         {duration:.2f}s")
    print(f"  Output Path:               {output_path}")
    print("=" * 65)

    final_df.select("source_ip", "attack_type", "label", "features").show(5, truncate=False)

    spark.stop()
    return final_count


if __name__ == "__main__":
    build_features()
