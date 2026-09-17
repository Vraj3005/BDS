# MongoDB Scripts

This directory will contain:
- `init_sharding.js`: Script to initialize shards and enable sharding on database/collections.
- `create_indexes.py`: Creates indexes on `timestamp`, `source_ip`, and `attack_type`.
- `verify_cluster.py`: Checks `sh.status()` and prints record counts across Shard 1 and Shard 2.
