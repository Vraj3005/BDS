# Distributed Cyber Threat Intelligence and Intrusion Analytics Platform

A Big Data platform built with **MongoDB Sharded Cluster**, **Hadoop HDFS**, and **Apache Spark (PySpark MLlib)** to collect, store, and analyze millions of network security logs (CICIDS2017) to detect cyber attacks, profile suspicious IPs, and visualize real-time threat intelligence.

---

## 🏗️ System Architecture (3-Node Cluster)

```
                         ┌────────────────────────────────────────┐
                         │              MASTER NODE               │
                         ├────────────────────────────────────────┤
                         │  MongoDB Router (mongos :27017)        │
                         │  Spark Master (:7077)                  │
                         │  Hadoop NameNode (:9000)               │
                         │  Resource Manager (:8032)              │
                         └───────────────────┬────────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
        ┌──────────────▼──────────────┐             ┌──────────────▼──────────────┐
        │        WORKER NODE 1        │             │        WORKER NODE 2        │
        ├─────────────────────────────┤             ├─────────────────────────────┤
        │  MongoDB Shard 1 (:27018)   │             │  MongoDB Shard 2 (:27019)   │
        │  Hadoop DataNode (:9866)    │             │  Hadoop DataNode (:9866)    │
        │  Spark Worker 1 (:7078)     │             │  Spark Worker 2 (:7079)     │
        └─────────────────────────────┘             └─────────────────────────────┘
```

---

## 🚀 Data Pipeline Workflow

```
CICIDS2017 CSV Logs
        │
        ├───────────────────────────────┐
        ▼                               ▼
 MongoDB Sharded Cluster       Hadoop HDFS Storage
 (Document log store)          (Distributed raw store)
                                        │
                                        ▼
                                   Apache Spark
                            (ETL, Filtering, Cleaning)
                                        │
                      ┌─────────────────┴─────────────────┐
                      ▼                                   ▼
             Threat Analytics                 PySpark MLlib Classifier
         (Attack stats, timeline,              (Decision Tree & Random
             top attacking IPs)                   Forest Detection)
                      │                                   │
                      └─────────────────┬─────────────────┘
                                        ▼
                            Threat Intelligence Engine
                         (0-100 IP Risk Score Assessment)
                                        │
                                        ▼
                              MongoDB Analytics DB
                      (attack_stats, ip_reputation, etc.)
                                        │
                                        ▼
                            Streamlit Web Dashboard
                       (Interactive KPIs, Charts, Health)
```

---

## 👥 Team Responsibilities & Ownership

| Member | Primary Role | Core Modules & Deliverables |
| :--- | :--- | :--- |
| **Member 1** | MongoDB + Data Engineer | Database schema, Ingestion pipeline (`csv_to_mongodb.py`), MongoDB sharding setup, Cluster verification |
| **Member 2** | Big Data Processing Engineer | Hadoop HDFS setup, Apache Spark cluster, PySpark ETL & cleaning, Distributed threat analytics |
| **Member 3** | ML & Visualization Engineer | PySpark ML models (Random Forest / Decision Tree), IP Risk Scoring engine, Streamlit Dashboard |

---

## 📁 Repository Structure

```
.
├── .env.example              # Sample environment configurations
├── .gitignore                # Git ignore rules for Big Data artifacts
├── README.md                 # Project root documentation
├── requirements.txt          # Python dependencies
├── config/                   # Centralized configuration loader
│   ├── __init__.py
│   └── settings.py
├── data/                     # Raw and processed security datasets
│   ├── raw/                  # Raw CSV files (CICIDS2017)
│   └── processed/            # Cleaned Parquet datasets
├── mongodb/                  # MongoDB configurations and sharding scripts
│   ├── config/
│   └── scripts/
├── hadoop/                   # Hadoop cluster configurations and setup
│   ├── config/
│   └── scripts/
├── spark/                    # Apache Spark jobs, ETL, and analytics
│   ├── jobs/
│   ├── preprocessing/
│   └── analytics/
├── ml/                       # Machine learning models and risk scoring
│   ├── training/
│   ├── models/
│   ├── prediction/
│   └── risk_engine/
├── ingestion/                # CSV data loaders for MongoDB and HDFS
├── dashboard/                # Streamlit cyber threat dashboard
├── docs/                     # Architecture and professor demo documentation
│   ├── architecture.md
│   └── demo_guide.md
└── tests/                    # Foundation and integration test suite
    ├── __init__.py
    └── test_foundation.py
```

---

## 📦 Step-by-Step GitHub Commit Roadmap

Follow these commits sequentially as each phase is completed:

| # | Commit Message | Module | Lead |
| :-: | :--- | :--- | :--- |
| **01** | `Initial project scaffold, environment config, and documentation` | Phase 0 (Scaffold) | All |
| **02** | `Added CICIDS2017 schema definition and sample log generator` | Phase 1 (Dataset) | Member 2 |
| **03** | `Implemented MongoDB data ingestion pipeline` | Phase 2 (Ingestion) | Member 1 |
| **04** | `Added MongoDB collection schemas and indexing scripts` | Phase 2 (MongoDB) | Member 1 |
| **05** | `Added MongoDB sharded cluster configuration and docker-compose` | Phase 3 (Sharding) | Member 1 |
| **06** | `Added MongoDB cluster verification and shard status check` | Phase 3 (Sharding) | Member 1 |
| **07** | `Configured Hadoop HDFS cluster and environment templates` | Phase 4 (Hadoop) | Member 2 |
| **08** | `Added HDFS data upload and block distribution verification` | Phase 4 (Hadoop) | Member 2 |
| **09** | `Configured Apache Spark master-worker cluster definitions` | Phase 5 (Spark) | Member 2 |
| **10** | `Implemented Spark ETL pipeline for log cleansing and deduplication` | Phase 6 (Spark ETL) | Member 2 |
| **11** | `Added categorical encoding and feature extraction transformations` | Phase 6 (Spark ETL) | Member 2 |
| **12** | `Implemented attack statistics and distribution aggregation job` | Phase 7 (Analytics) | Member 2 |
| **13** | `Added IP threat frequency and network timeline analysis` | Phase 7 (Analytics) | Member 2 |
| **14** | `Implemented PySpark ML pipeline with DecisionTree and RandomForest` | Phase 8 (ML) | Member 3 |
| **15** | `Added model evaluation, confusion matrix, and attack predictor` | Phase 8 (ML) | Member 3 |
| **16** | `Implemented IP reputation engine and risk score calculator` | Phase 9 (Risk Engine) | Member 3 |
| **17** | `Integrated Spark analytics and ML inference results into MongoDB` | Phase 10 (Integration) | Member 1 & 2 |
| **18** | `Built Streamlit cybersecurity dashboard with KPI and attack charts` | Phase 11 (Dashboard) | Member 3 |
| **19** | `Added cluster health monitoring view to dashboard` | Phase 11 (Dashboard) | Member 3 |
| **20** | `Added end-to-end integration test and automated demonstration runner` | Phase 12 (Demo) | All |

---

## ⚡ Quickstart & Local Setup

### 1. Clone & Set Up Environment
```bash
git clone <your-github-repo-url>
cd INNOV

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1
# (Linux / Mac / Git Bash)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Verify Foundation
```bash
python -m unittest tests/test_foundation.py
```
