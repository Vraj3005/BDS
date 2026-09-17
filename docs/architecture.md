# System Architecture

## 3-Node Distributed Topology

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

## Data Pipeline Architecture

```
                    CICIDS2017 Security Logs (CSV)
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
         MongoDB Sharded Cluster        Hadoop HDFS Storage
         (Queryable raw logs)           (Distributed block storage)
                                                  │
                                                  ▼
                                            Apache Spark
                                      (Distributed Processing)
                                                  │
                                 ┌────────────────┴────────────────┐
                                 │                                 │
                                 ▼                                 ▼
                         Feature Engineering             Threat Analytics
                                 │                       (Attacks, IPs, Timeline)
                                 ▼                                 │
                          PySpark MLlib                            │
                    (Random Forest Classifier)                     │
                                 │                                 │
                                 └────────────────┬────────────────┘
                                                  │
                                                  ▼
                                      Threat Intelligence Engine
                                      (Risk Score 0-100 Calculation)
                                                  │
                                                  ▼
                                            MongoDB Storage
                                   (Analytics & Prediction Results)
                                                  │
                                                  ▼
                                         Streamlit Dashboard
                                    (KPIs, Charts, Cluster Health)
```
