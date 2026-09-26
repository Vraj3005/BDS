#!/usr/bin/env bash
# Apache Spark Environment Configuration for 3-Node BDS Cluster
# Master: master | Workers: worker1, worker2

# Java & Hadoop configuration
export JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-11-openjdk}
export HADOOP_CONF_DIR=${HADOOP_CONF_DIR:-/opt/hadoop/etc/hadoop}

# Spark Master configuration
export SPARK_MASTER_HOST="master"
export SPARK_MASTER_PORT=7077
export SPARK_MASTER_WEBUI_PORT=8080

# Spark Worker configuration (Worker 1 & Worker 2)
export SPARK_WORKER_CORES=2
export SPARK_WORKER_MEMORY="2g"
export SPARK_WORKER_PORT=7078
export SPARK_WORKER_WEBUI_PORT=8081

# Spark Driver & Executor Memory
export SPARK_DRIVER_MEMORY="2g"
export SPARK_EXECUTOR_MEMORY="2g"

# Logs & PID directory
export SPARK_LOG_DIR="/var/log/spark"
export SPARK_PID_DIR="/var/run/spark"
