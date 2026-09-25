#!/bin/bash
# Verifies block distribution across Worker 1 and Worker 2.

echo "Checking HDFS basic report..."
hdfs dfsadmin -report

echo "------------------------------------------------"
echo "Checking block distribution for /cybersecurity/CICIDS2017.csv..."
hdfs fsck /cybersecurity/CICIDS2017.csv -files -blocks -locations

echo "Block verification complete."
