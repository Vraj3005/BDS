import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# Fields definition based on data/README.md
FIELDS = [
    'timestamp', 'source_ip', 'destination_ip', 'protocol', 
    'flow_duration', 'packet_length', 'total_bytes', 
    'packet_count', 'attack_type', 'severity'
]

PROTOCOLS = ['TCP', 'UDP', 'ICMP']
ATTACK_TYPES = ['BENIGN', 'DDoS', 'PortScan', 'Botnet', 'BruteForce']
SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_row(start_time):
    attack = random.choice(ATTACK_TYPES)
    
    # Simple logic to assign severity based on attack type
    if attack == 'BENIGN':
        severity = 'Low'
    elif attack in ['PortScan']:
        severity = random.choice(['Low', 'Medium'])
    elif attack in ['Botnet', 'BruteForce']:
        severity = random.choice(['Medium', 'High'])
    else: # DDoS
        severity = random.choice(['High', 'Critical'])

    return {
        'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'source_ip': random_ip(),
        'destination_ip': random_ip(),
        'protocol': random.choice(PROTOCOLS),
        'flow_duration': random.randint(1000, 1000000),
        'packet_length': random.randint(40, 65535),
        'total_bytes': random.randint(100, 10000000),
        'packet_count': random.randint(1, 10000),
        'attack_type': attack,
        'severity': severity
    }

def generate_sample(file_path: Path, num_rows: int = 5000):
    print(f"Generating {num_rows} synthetic logs to {file_path}...")
    
    # Ensure parent directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    start_time = datetime(2026, 8, 26, 10, 30, 22)
    
    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        
        for i in range(num_rows):
            writer.writerow(generate_row(start_time))
            # Increment time by random milliseconds up to a few seconds
            start_time += timedelta(milliseconds=random.randint(10, 2000))
            
            if (i + 1) % 1000 == 0:
                print(f"  Generated {i + 1} rows...")
                
    print("Generation complete.")

if __name__ == '__main__':
    base_dir = Path(__file__).resolve().parent.parent
    sample_file = base_dir / 'data' / 'raw' / 'sample_cicids2017.csv'
    generate_sample(sample_file, 5000)
