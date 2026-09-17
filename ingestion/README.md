# Data Ingestion Module

Provides high-throughput ingestion pipelines from raw CSV logs into MongoDB and HDFS.

## Responsibilities (Lead: Member 1 & 2)
- Phase 2: `csv_to_mongodb.py` (chunked ingestion with bulk inserts)
- Phase 4: `upload_to_hdfs.py` (HDFS client / WebHDFS ingestion)

## Features
- Chunk-based processing to handle millions of lines without memory overflow.
- Automatic field type casting and JSON structure generation.
- Progress reporting and execution rate statistics.
