#!/bin/bash
# Helper command to put raw CSV dataset into /cybersecurity.

LOCAL_DATA_PATH="../../data/raw/CICIDS2017.csv"
HDFS_DEST_PATH="/cybersecurity/CICIDS2017.csv"

if [ ! -f "$LOCAL_DATA_PATH" ]; then
    echo "Error: Local data file $LOCAL_DATA_PATH not found!"
    echo "Make sure you have generated the sample data or placed it in the right path."
    exit 1
fi

echo "Uploading $LOCAL_DATA_PATH to HDFS $HDFS_DEST_PATH..."
hdfs dfs -put -f "$LOCAL_DATA_PATH" "$HDFS_DEST_PATH"

echo "Upload complete. Verifying file in HDFS:"
hdfs dfs -ls /cybersecurity
