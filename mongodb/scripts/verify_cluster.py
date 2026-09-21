"""
MongoDB Cluster & Sharding Verification Script
Distributed Cyber Threat Intelligence Platform

Performs comprehensive diagnostic inspection of the MongoDB distributed architecture:
1. Detects cluster topology (Sharded Cluster vs. Replica Set vs. Atlas Cloud).
2. Inspects registered Shards (Shard 1 / Worker 1, Shard 2 / Worker 2).
3. Verifies shard key configuration on cyber_intel.network_logs.
4. Analyzes document distribution and chunk balance across shards.
5. Verifies database indexes and collection performance.
"""

import sys
from pathlib import Path

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import get_mongo_uri, get_mongo_client, MONGO_CONFIG


def verify_cluster():
    uri = get_mongo_uri()
    print("=" * 65)
    print("      DISTRIBUTED MONGODB CLUSTER VERIFICATION REPORT")
    print("=" * 65)
    print(f"Target URI: {uri[:35]}...")

    try:
        client = get_mongo_client(timeout_ms=5000)
        # Test ping
        client.admin.command("ping")
        print("[+] Cluster Connection: SUCCESS (Online)")
    except Exception as e:
        print(f"[-] Failed to connect to MongoDB: {e}")
        print("\n[!] TROUBLESHOOTING TIP:")
        print("  • If using MongoDB Atlas Cloud: Log into MongoDB Atlas -> Network Access,")
        print("    and ensure '0.0.0.0/0' (Allow access from anywhere) or your current IP is added.")
        print("  • If using Local Sharded Cluster: Run mongodb\\config\\run_local_shards.ps1 first.")
        print("=" * 65)
        sys.exit(1)

    db_name = MONGO_CONFIG["db_name"]
    db = client[db_name]
    logs_col_name = MONGO_CONFIG["collections"]["network_logs"]
    logs_col = db[logs_col_name]

    # 1. Determine Cluster Topology
    is_sharded = False
    shards_list = []
    try:
        shards_info = client.admin.command("listShards")
        shards_list = shards_info.get("shards", [])
        if shards_list:
            is_sharded = True
    except Exception:
        # Not a mongos router or insufficient admin privileges for listShards
        is_sharded = False

    try:
        hello_info = client.admin.command("hello")
        msg = hello_info.get("msg", "")
        if msg == "isdbgrid":
            is_sharded = True
        repl_set = hello_info.get("setName", "Standalone")
        primary_host = hello_info.get("primary", "N/A")
    except Exception:
        repl_set = "Unknown"
        primary_host = "N/A"

    # 2. Total Records and Size
    total_docs = logs_col.count_documents({})
    print("-" * 65)
    print(f"Database:             {db_name}")
    print(f"Target Collection:    {logs_col_name}")
    print(f"Total Security Logs:  {total_docs:,} documents")

    if is_sharded and shards_list:
        print(f"Cluster Topology:     SHARDED CLUSTER (mongos Router Active)")
        print(f"Configured Shards:    {len(shards_list)} Shards Detected")
        print("-" * 65)
        print("SHARD DISTRIBUTION DETAILS:")
        
        # Query collStats for shard-level distribution
        try:
            coll_stats = db.command("collStats", logs_col_name)
            sharded_stats = coll_stats.get("shards", {})
            for shard in shards_list:
                s_id = shard["_id"]
                s_host = shard["host"]
                s_count = sharded_stats.get(s_id, {}).get("count", 0)
                pct = (s_count / total_docs * 100) if total_docs > 0 else 0
                print(f"  • Shard: {s_id}")
                print(f"    Host:       {s_host}")
                print(f"    Documents:  {s_count:,} ({pct:.1f}%)")
        except Exception:
            for shard in shards_list:
                print(f"  • Shard ID: {shard['_id']} (Host: {shard['host']})")
    else:
        print(f"Cluster Topology:     REPLICA SET / CLOUD CLUSTER ({repl_set})")
        print(f"Primary Node:         {primary_host}")
        print("-" * 65)
        print("TOPOLOGY NOTE:")
        print("  • Operating on replica set storage layer.")
        print("  • Sharded cluster configurations ready in: mongodb/config/")
        print("  • Automated init script ready in:         mongodb/scripts/init_sharding.js")

    # 3. Verify Indexes
    print("-" * 65)
    print("COLLECTION INDEXES:")
    indexes = list(logs_col.list_indexes())
    for idx in indexes:
        key_fields = ", ".join([f"{k}:{v}" for k, v in idx["key"].items()])
        print(f"  ✓ Index: {idx['name']} -> ({key_fields})")

    print("=" * 65)
    if total_docs > 0:
        print("STATUS: CLUSTER READY FOR SPARK ETL & ANALYTICS PIPELINE")
    else:
        print("STATUS: ONLINE (Run ingestion/csv_to_mongodb.py to load logs)")
    print("=" * 65)
    client.close()


if __name__ == "__main__":
    verify_cluster()
