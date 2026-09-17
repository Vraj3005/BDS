# Hadoop HDFS Module

Responsible for distributed file storage, holding the raw network log datasets and providing fault-tolerant block-based distribution across worker nodes.

## Responsibilities (Lead: Member 2)
- Phase 4: NameNode and DataNode deployment (NameNode on Master, DataNode on Worker 1 and Worker 2)
- HDFS folder initialization (`/cybersecurity`)
- Raw dataset uploading and block verification (`hdfs dfsadmin -report`)

## Directory Structure
- `config/`: XML configuration templates (`core-site.xml`, `hdfs-site.xml`).
- `scripts/`: Shell and Python scripts for cluster setup, uploading files, and block inspections.
