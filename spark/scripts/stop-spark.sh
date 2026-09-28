#!/bin/bash
# Script to stop the local Spark cluster

echo "Stopping Spark Workers..."
$SPARK_HOME/sbin/stop-worker.sh

echo "Stopping Spark Master..."
$SPARK_HOME/sbin/stop-master.sh

echo "Spark cluster stopped successfully."
