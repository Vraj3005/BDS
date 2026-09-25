#!/bin/bash
# Script to format NameNode, start HDFS daemons, and create default directories.

echo "Formatting NameNode..."
hdfs namenode -format -force

echo "Starting HDFS daemons..."
start-dfs.sh

echo "Waiting for NameNode to exit safemode..."
hdfs dfsadmin -safemode wait

echo "Creating default HDFS directories..."
hdfs dfs -mkdir -p /cybersecurity
hdfs dfs -mkdir -p /user/spark
hdfs dfs -chmod -R 777 /cybersecurity

echo "HDFS setup complete."
