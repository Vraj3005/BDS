# MongoDB Scripts

This directory contains database management and cluster administration scripts:

## Scripts Overview

1. **`init_sharding.js`**:
   - Automated JavaScript script for Mongo Shell (`mongosh`).
   - Initializes replica sets (`cfgReplSet`, `shard1ReplSet`, `shard2ReplSet`).
   - Registers Shard 1 and Shard 2 with the Query Router.
   - Enables sharding on database `cyber_intel` and shards `network_logs` with a hashed key on `{ "source_ip": "hashed" }`.
   ```bash
   mongosh --port 27017 < mongodb/scripts/init_sharding.js
   ```

2. **`create_indexes.py`**:
   - Connects to the database and builds ascending indexes on `timestamp`, `source_ip`, and `attack_type`.
   ```bash
   python mongodb/scripts/create_indexes.py
   ```

3. **`verify_cluster.py`**:
   - Inspects cluster health, detects node topology (Sharded Cluster vs. Replica Set), checks document counts, and prints chunk distributions across Shard 1 and Shard 2.
   ```bash
   python mongodb/scripts/verify_cluster.py
   ```
