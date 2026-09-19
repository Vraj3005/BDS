import sys
from pathlib import Path
from pymongo import MongoClient, ASCENDING

# Add project root to sys.path to allow importing config
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(base_dir))

from config.settings import get_mongo_uri, MONGO_CONFIG

def create_indexes():
    uri = get_mongo_uri()
    print(f"Connecting to MongoDB at {uri}...")
    
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Force a connection test
        client.admin.command('ping')
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        print("Please ensure MongoDB is running.")
        sys.exit(1)
        
    db_name = MONGO_CONFIG["db_name"]
    db = client[db_name]
    
    logs_col_name = MONGO_CONFIG["collections"]["network_logs"]
    logs_col = db[logs_col_name]
    
    print(f"Creating indexes on {db_name}.{logs_col_name}...")
    
    # Create indexes on timestamp, source_ip, and attack_type
    logs_col.create_index([("timestamp", ASCENDING)])
    logs_col.create_index([("source_ip", ASCENDING)])
    logs_col.create_index([("attack_type", ASCENDING)])
    
    print("Indexes created successfully. Current indexes:")
    for index in logs_col.list_indexes():
        print(f" - {index['name']}: {index['key']}")
        
    client.close()

if __name__ == "__main__":
    create_indexes()
