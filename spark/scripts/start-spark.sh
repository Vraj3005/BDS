#!/bin/bash
# Script to start Spark Master and 2 Workers locally for development

echo "Starting Spark Master on port 7077..."
$SPARK_HOME/sbin/start-master.sh -h localhost -p 7077 --webui-port 8080

echo "Starting Spark Worker 1 on port 7078..."
$SPARK_HOME/sbin/start-worker.sh spark://localhost:7077 -c 2 -m 4G -p 7078 --webui-port 8081

echo "Starting Spark Worker 2 on port 7079..."
$SPARK_HOME/sbin/start-worker.sh spark://localhost:7077 -c 2 -m 4G -p 7079 --webui-port 8082

echo "Spark cluster started successfully."
echo "Master Web UI: http://localhost:8080"
