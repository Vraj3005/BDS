# Apache Spark Configuration

This directory contains standalone and multi-node cluster configurations for the 3-node topology:
- **Master Node**:
  - `spark-env.sh`: Environment variables for master host, worker resources, and paths.
  - `spark-defaults.conf`: Performance tunings (Kryo serializer, default partitions, memory thresholds).
  - `workers`: Worker list (`worker1`, `worker2`) mapping to Worker Node 1 and Worker Node 2.
- **Container Deployment**:
  - `docker-compose-spark.yml`: Multi-node cluster with `spark-master` (:8080 / :7077), `spark-worker-1` (:8081), and `spark-worker-2` (:8082).
