import sys
import pandas as pd
from pathlib import Path
from pymongo import MongoClient

# Add project root to sys.path
base_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(base_dir))

from config.settings import get_mongo_uri, get_mongo_client, MONGO_CONFIG, PATH_CONFIG

def ingest_data(chunk_size=1000):
    csv_file = PATH_CONFIG["sample_csv"]
    if not csv_file.exists():
        print(f"Error: CSV file not found at {csv_file}")
        sys.exit(1)

    uri = get_mongo_uri()
    print(f"Connecting to MongoDB at {uri[:35]}...")
    try:
        client = get_mongo_client(timeout_ms=10000)
        client.admin.command('ping')
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        sys.exit(1)

    db_name = MONGO_CONFIG["db_name"]
    db = client[db_name]
    logs_col_name = MONGO_CONFIG["collections"]["network_logs"]
    logs_col = db[logs_col_name]

    print(f"Starting ingestion from {csv_file} to {db_name}.{logs_col_name}...")
    
    total_inserted = 0
    
    # Define data types for pandas
    dtypes = {
        'timestamp': str,
        'source_ip': str,
        'destination_ip': str,
        'protocol': str,
        'flow_duration': 'Int64', # Nullable integer type
        'packet_length': 'Int64',
        'total_bytes': 'Int64',
        'packet_count': 'Int64',
        'attack_type': str,
        'severity': str
    }

    try:
        # Read in chunks
        for chunk in pd.read_csv(csv_file, chunksize=chunk_size, dtype=dtypes):
            # Convert pandas NA to python None
            chunk = chunk.where(pd.notnull(chunk), None)
            records = chunk.to_dict('records')
            if records:
                logs_col.insert_many(records)
                total_inserted += len(records)
                print(f"Inserted {total_inserted} records...")
    except Exception as e:
        print(f"Error during ingestion: {e}")
    finally:
        client.close()
        print(f"Ingestion complete. Total records inserted: {total_inserted}")

if __name__ == "__main__":
    ingest_data(chunk_size=1000)
