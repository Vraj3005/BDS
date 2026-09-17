# MongoDB Module

Responsible for storing network logs, aggregation statistics, and threat intelligence scores in a document-based NoSQL architecture.

## Responsibilities (Lead: Member 1)
- Phase 2: Single node prototype & collection indexing
- Phase 3: Sharded cluster configuration (Router `mongos`, Config Server, Shard 1, Shard 2)
- Phase 10: Storing analytics and prediction results back into MongoDB

## Directory Structure
- `config/`: Configuration files for MongoDB daemon (`mongod.conf`), config server, and router (`mongos.conf`).
- `scripts/`: Initialization scripts for replica sets, shard activation (`sh.addShard()`), indexing, and status checking.
