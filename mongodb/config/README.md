# MongoDB Sharded Cluster Configurations

This directory defines the 3-node distributed topology:
- **Master Node**:
  - `mongos.conf`: MongoDB Query Router (`mongos`) configuration listening on port `27017` and routing queries to Shard 1 and Shard 2 via the config database.
  - `configsvr.conf`: Config Server replica set (`cfgReplSet`) configuration on port `27019` holding cluster metadata and routing tables.
- **Worker Node 1**:
  - `shard1.conf`: Shard 1 (`shard1ReplSet`) configuration on port `27018` storing partition 1 of the dataset.
- **Worker Node 2**:
  - `shard2.conf`: Shard 2 (`shard2ReplSet`) configuration on port `27028` storing partition 2 of the dataset.

## Cluster Launch Options

### Option 1: Docker Compose (Recommended for Containerized Multi-Node)
```bash
docker compose -f mongodb/config/docker-compose-sharding.yml up -d
```

### Option 2: Local Windows Multi-Instance Launcher
```powershell
powershell -ExecutionPolicy Bypass -File mongodb/config/run_local_shards.ps1
```
