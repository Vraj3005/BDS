// ==========================================================
// MongoDB Sharded Cluster Initialization Script
// Distributed Cyber Threat Intelligence Platform
// ==========================================================

print(">>> Initializing MongoDB Sharded Cluster for BDS Project...");

// 1. Initialize Config Server Replica Set
try {
    let cfgConn = new Mongo("localhost:27019");
    let cfgAdmin = cfgConn.getDB("admin");
    let cfgStatus = cfgAdmin.runCommand({ replSetGetStatus: 1 });
    if (!cfgStatus.ok) {
        print("Initializing Config Server Replica Set (cfgReplSet)...");
        cfgAdmin.runCommand({
            replSetInitiate: {
                _id: "cfgReplSet",
                configsvr: true,
                members: [{ _id: 0, host: "localhost:27019" }]
            }
        });
    }
} catch (e) {
    print("Config server replica check/init completed: " + e);
}

// 2. Initialize Shard 1 Replica Set (Worker 1)
try {
    let s1Conn = new Mongo("localhost:27018");
    let s1Admin = s1Conn.getDB("admin");
    let s1Status = s1Admin.runCommand({ replSetGetStatus: 1 });
    if (!s1Status.ok) {
        print("Initializing Shard 1 Replica Set (shard1ReplSet)...");
        s1Admin.runCommand({
            replSetInitiate: {
                _id: "shard1ReplSet",
                members: [{ _id: 0, host: "localhost:27018" }]
            }
        });
    }
} catch (e) {
    print("Shard 1 replica check/init completed: " + e);
}

// 3. Initialize Shard 2 Replica Set (Worker 2)
try {
    let s2Conn = new Mongo("localhost:27028");
    let s2Admin = s2Conn.getDB("admin");
    let s2Status = s2Admin.runCommand({ replSetGetStatus: 1 });
    if (!s2Status.ok) {
        print("Initializing Shard 2 Replica Set (shard2ReplSet)...");
        s2Admin.runCommand({
            replSetInitiate: {
                _id: "shard2ReplSet",
                members: [{ _id: 0, host: "localhost:27028" }]
            }
        });
    }
} catch (e) {
    print("Shard 2 replica check/init completed: " + e);
}

// 4. Register Shards with Query Router (mongos on port 27017)
print(">>> Connecting to mongos Query Router on port 27017...");
try {
    let routerConn = new Mongo("localhost:27017");
    let adminDB = routerConn.getDB("admin");

    print("Adding Shard 1 (Worker 1)...");
    sh.addShard("shard1ReplSet/localhost:27018");

    print("Adding Shard 2 (Worker 2)...");
    sh.addShard("shard2ReplSet/localhost:27028");

    // 5. Enable Sharding on Project Database
    print("Enabling sharding for database: cyber_intel...");
    sh.enableSharding("cyber_intel");

    // 6. Shard Network Logs Collection with Hashed Shard Key
    print("Sharding collection: cyber_intel.network_logs on { source_ip: 'hashed' }...");
    sh.shardCollection("cyber_intel.network_logs", { "source_ip": "hashed" });

    print(">>> Sharding successfully configured!");
    print(">>> Printing sh.status():");
    sh.status();
} catch (e) {
    print("Router configuration note: " + e);
}
