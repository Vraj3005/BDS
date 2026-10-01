# Distributed Cyber Threat Intelligence Platform -- Demonstration & Defense Guide

Comprehensive architecture, testing, and viva defense guide for the **Distributed Cyber Threat Intelligence and Intrusion Analytics Platform** built with **MongoDB**, **Apache Hadoop**, **Apache Spark (PySpark MLlib)**, and **Streamlit**.

---

## 1. System Architecture Overview

The platform implements an enterprise Security Operations Center (SOC) Big Data architecture across a **3-Node Distributed Cluster**:

```
                       +-----------------------+
                       |      MASTER NODE      |
                       |  - MongoDB Router     |
                       |  - Spark Master:7077  |
                       |  - Hadoop NameNode    |
                       |  - Streamlit UI:8501  |
                       +-----------+-----------+
                                   |
                  +----------------+----------------+
                  |                                 |
        +---------+---------+             +---------+---------+
        |   WORKER NODE 1   |             |   WORKER NODE 2   |
        |  - Spark Worker 1 |             |  - Spark Worker 2 |
        |  - Hadoop DataNode|             |  - Hadoop DataNode|
        |  - MongoDB Shard 1|             |  - MongoDB Shard 2|
        +-------------------+             +-------------------+
```

### Component Roles & Big Data Rationale:
1. **MongoDB (Document-Oriented NoSQL Store)**:
   - *Why NoSQL over RDBMS:* Network telemetry arrives in heterogeneous JSON/BSON structures with varying flow attributes. MongoDB provides high-throughput sharded ingestion and flexible schemas for real-time threat intelligence queries.
2. **Apache Hadoop HDFS (Distributed File Storage)**:
   - *Why HDFS:* Provides cost-effective, fault-tolerant cold storage for raw multi-gigabyte PCAP and CSV logs across cluster DataNodes.
3. **Apache Spark & PySpark MLlib (Distributed In-Memory Compute Engine)**:
   - *Why Spark over Pandas/Scikit-Learn:* Pandas and Scikit-Learn require all records to fit into single-node RAM. Spark distributes RDD/DataFrame partitions across worker nodes, enabling distributed ETL, parallel multi-dimensional aggregations, and distributed ensemble model training.
4. **Streamlit (Security Analyst Web Dashboard)**:
   - Provides security analysts and SOC managers with live KPI metrics, threat distribution charts, attack timelines, IP reputation lookups, and cluster health monitoring.

---

## 2. Complete End-to-End Pipeline (Phases 1 to 12)

```
[Raw Logs: CICIDS2017] 
       │
       ▼
[Phase 2: Ingestion & Storage] ──► MongoDB / HDFS
       │
       ▼
[Phase 6: Spark Distributed ETL] ──► Deduplication, cleansing, schema casting (cleaned_logs.parquet)
       │
       ▼
[Phase 6: Feature Engineering] ──► VectorAssembler, StringIndexer, StandardScaler (features.parquet)
       │
       ├───────────────────────────────────────────┐
       ▼                                           ▼
[Phase 7: Distributed Analytics]        [Phase 8: PySpark MLlib]
  - Attack Type Share                     - Decision Tree Classifier
  - Protocol Breakdown                    - Random Forest Classifier (20 trees)
  - Hourly Intensity & Surges             - 5x5 Multi-Class Confusion Matrix
  - Top 50 Attacker/Target IPs            - Dynamic Confidence Inference
       │                                           │
       └─────────────────────┬─────────────────────┘
                             ▼
            [Phase 9: Threat Intelligence Engine]
              - Multi-factor IP Risk Scoring (0-100)
              - Threat Tiers: Low, Medium, High, Critical
              - Automated Defense Action Policies
                             │
                             ▼
            [Phase 10: Data Integration Layer]
              - MongoDB Collections (attack_stats, timeline, ip_reputation, predictions)
              - Local resilient JSON cache for sub-second offline rendering
                             │
                             ▼
            [Phase 11: Cybersecurity Dashboard]
              - Streamlit Multi-Page Threat Intelligence UI
              - Cluster Health & Infrastructure Monitor
                             │
                             ▼
            [Phase 12: Automated Demo & Validation]
              - Single-Command Demo Runner (`run_platform.py`)
              - Full 8-stage End-to-End Integration Test Suite
```

---

## 3. Machine Learning & Threat Scoring Formulation

### A. Distributed Classification (PySpark MLlib)
- **Features (8 dimensions)**: `flow_duration`, `packet_count`, `packet_length`, `total_bytes`, `hour`, `day_of_week`, `protocol_index`, `severity_index`.
- **Pipeline Transformations**:
  1. `StringIndexer`: Encodes categorical fields into zero-indexed numeric categories.
  2. `VectorAssembler`: Combines numeric and categorical features into a single `DenseVector`.
  3. `StandardScaler`: Normalizes feature variances to eliminate feature dominance.
- **Model Selection**: Random Forest Classifier (`numTrees=20`, `maxDepth=8`) outperforms single Decision Trees by ensembling uncorrelated trees, achieving higher generalized accuracy on noisy intrusion patterns.

### B. Dynamic IP Risk Scoring Formula (0 to 100)
For each unique Source IP, the platform computes a composite threat reputation score:

$$\text{Risk Score} = \min\big(100, \; \text{Frequency Score} + \text{Severity Multiplier} + \text{Dispersion Score}\big)$$

1. **Attack Frequency Score (up to 40 pts)**:
   $$\min(40, \; \text{Attack Count} \times 4)$$
2. **Attack Severity Multiplier (up to 40 pts)**:
   - $\text{DDoS} = 40$ pts
   - $\text{Botnet} = 30$ pts
   - $\text{BruteForce} = 25$ pts
   - $\text{PortScan} = 15$ pts
   - $\text{BENIGN} = 0$ pts
3. **Target Dispersion / Blast Radius (up to 20 pts)**:
   $$\min(20, \; \text{Unique Destination Targets} \times 4)$$
4. **Threat Tiers & Automated SOC Defense Actions**:
   - **76 - 100 (Critical)**: `Auto-Block & Quarantine` (Immediate perimeter firewall isolation).
   - **51 - 75 (High)**: `Active Firewall Throttle` (Bandwidth restriction and active session termination).
   - **26 - 50 (Medium)**: `Rate-limit & Deep Inspection` (Packet payload inspection and rate limiting).
   - **0 - 25 (Low)**: `Standard Network Monitoring` (Normal baseline traffic).

---

## 4. Evaluation & Demonstration Commands

### Step 1: Run the Master Platform Demonstration
Showcases all 6 pipeline stages in the terminal with structured tables:
```bash
python run_platform.py
```

### Step 2: Interactive Threat Actor IP Lookup
Look up the full intelligence profile and defense policy for any suspicious IP:
```bash
python run_platform.py --ip 13.93.219.67
```

### Step 3: Run the Complete End-to-End System Test Suite
Executes the comprehensive Phase 12 validation suite:
```bash
python -m unittest tests/test_phase12_e2e.py
```

### Step 4: Launch the Streamlit Cyber Threat Center
Launches the browser-based visualization dashboard:
```bash
streamlit run dashboard/app.py
```
*Open http://localhost:8501 to view:*
- **Overview & KPIs**: Total traffic, attack share %, active threat actors, high-risk ratio.
- **Threat Analytics**: Attack distribution donut, protocol breakdown, hourly cadence.
- **IP Threat Intelligence**: Scored threat actors, risk distributions, defense actions.
- **ML Intrusion Predictions**: Real-time classification confidence and severity gauges.
- **Cluster Status & Health**: Live health badges for MongoDB, Spark, and Hadoop nodes.

---

## 5. Viva / Presentation Q&A Preparation

| Question | Strong Answer |
| :--- | :--- |
| **Why not store logs in MySQL or PostgreSQL?** | Network security logs are generated at high velocities (gigabytes per minute) and have varying packet formats. RDBMS requires strict schemas and locks tables during heavy writes. MongoDB's document model natively ingests semi-structured JSON and horizontal sharding scales writes linearly across cluster shards. |
| **Why use Apache Spark instead of Python Pandas?** | Pandas loads data into single-machine memory. If the dataset exceeds RAM (e.g., 50GB log file), Pandas crashes with an Out-of-Memory (OOM) error. Spark distributes data into Resilient Distributed Datasets (RDDs) across Worker 1 and Worker 2, computing map-reduce transformations in parallel. |
| **How does PySpark train a Random Forest across multiple nodes?** | PySpark MLlib uses parallel tree construction. For each node split, Spark broadcasts the candidate split points and worker nodes calculate histograms and Gini impurity values on their local partitions in parallel, merging results at the master driver. |
| **How does the platform handle offline conditions or cloud connectivity interruptions?** | The platform features a dual-resilient data layer: analytical outputs are stored in MongoDB Atlas, while automated Parquet and JSON pipeline caches guarantee that CLI tools and the Streamlit dashboard function with zero dependencies during presentations or disconnected evaluations. |
