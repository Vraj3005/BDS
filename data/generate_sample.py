"""
Synthetic CICIDS2017 Security Log Generator
Distributed Cyber Threat Intelligence Platform

Generates realistic network intrusion logs in large volumes (e.g. 1 Lakh+ records)
with authentic threat actor behavior, repeat attacker IP pools, enterprise server
targets, and attack-correlated flow metrics.
"""

import csv
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path

FIELDS = [
    'timestamp', 'source_ip', 'destination_ip', 'protocol',
    'flow_duration', 'packet_length', 'total_bytes',
    'packet_count', 'attack_type', 'severity'
]

PROTOCOLS = ['TCP', 'UDP', 'ICMP']
ATTACK_TYPES = ['BENIGN', 'DDoS', 'PortScan', 'Botnet', 'BruteForce']


def build_ip_pools():
    """Build realistic pools of persistent threat actors, benign clients, and servers."""
    # 50 persistent high-volume attackers
    persistent_attackers = [
        f"192.168.1.{i}" for i in range(10, 60)
    ] + [
        f"45.33.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(30)
    ] + [
        f"185.220.101.{i}" for i in range(1, 21)
    ]

    # 300 moderate/occasional attackers
    occasional_attackers = [
        f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        for _ in range(300)
    ]

    # 1500 benign normal clients
    benign_clients = [
        f"10.0.{random.randint(1, 20)}.{random.randint(1, 254)}" for _ in range(500)
    ] + [
        f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}" for _ in range(500)
    ] + [
        f"192.168.100.{random.randint(1, 254)}" for _ in range(500)
    ]

    # 30 enterprise destination servers (DMZ, Web, API, DB, Mail, DNS)
    target_servers = [
        f"10.0.0.{i}" for i in range(1, 21)
    ] + [
        f"172.16.1.{i}" for i in range(1, 11)
    ]

    return persistent_attackers, occasional_attackers, benign_clients, target_servers


def generate_flow(start_time, persistent_attackers, occasional_attackers, benign_clients, target_servers):
    """Generate a single network flow record with realistic attack-correlated attributes."""
    # Weight attacks: 40% Benign, 25% DDoS, 15% PortScan, 10% BruteForce, 10% Botnet
    attack = random.choices(
        ATTACK_TYPES,
        weights=[40, 25, 15, 10, 10],
        k=1
    )[0]

    dest_ip = random.choice(target_servers)

    if attack == 'BENIGN':
        src_ip = random.choice(benign_clients)
        protocol = random.choice(['TCP', 'TCP', 'UDP'])
        flow_duration = random.randint(15000, 800000)
        packet_count = random.randint(5, 150)
        packet_length = random.randint(200, 1500)
        total_bytes = packet_count * packet_length
        severity = 'Low'

    elif attack == 'DDoS':
        # DDoS uses both persistent and random bots
        src_ip = random.choice(persistent_attackers if random.random() < 0.7 else occasional_attackers)
        protocol = random.choice(['TCP', 'UDP'])
        flow_duration = random.randint(500, 50000)      # very fast burst
        packet_count = random.randint(500, 10000)       # massive packet flood
        packet_length = random.randint(64, 512)
        total_bytes = packet_count * packet_length
        severity = random.choice(['High', 'Critical'])

    elif attack == 'PortScan':
        src_ip = random.choice(persistent_attackers if random.random() < 0.6 else occasional_attackers)
        protocol = 'TCP'
        flow_duration = random.randint(100, 5000)        # extremely brief probes
        packet_count = random.randint(1, 5)              # SYN probes
        packet_length = random.randint(40, 64)
        total_bytes = packet_count * packet_length
        severity = random.choice(['Low', 'Medium'])

    elif attack == 'BruteForce':
        src_ip = random.choice(occasional_attackers if random.random() < 0.5 else persistent_attackers)
        protocol = 'TCP'
        flow_duration = random.randint(50000, 1200000)
        packet_count = random.randint(50, 600)
        packet_length = random.randint(100, 800)
        total_bytes = packet_count * packet_length
        severity = random.choice(['Medium', 'High'])

    else:  # Botnet
        src_ip = random.choice(persistent_attackers)
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        flow_duration = random.randint(100000, 3000000)
        packet_count = random.randint(20, 400)
        packet_length = random.randint(150, 1200)
        total_bytes = packet_count * packet_length
        severity = random.choice(['High', 'Critical'])

    return {
        'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'protocol': protocol,
        'flow_duration': flow_duration,
        'packet_length': packet_length,
        'total_bytes': total_bytes,
        'packet_count': packet_count,
        'attack_type': attack,
        'severity': severity
    }


def generate_sample(file_path: Path, num_rows: int = 100000):
    print("=" * 65)
    print(f"  SYNTHETIC CICIDS2017 BIG DATASET GENERATOR ({num_rows:,} ROWS)")
    print("=" * 65)
    print(f"Target Output: {file_path}")

    file_path.parent.mkdir(parents=True, exist_ok=True)
    persistent_attackers, occasional_attackers, benign_clients, target_servers = build_ip_pools()

    print(f"Initialized IP Pools: {len(persistent_attackers)} Persistent Attackers, "
          f"{len(occasional_attackers)} Occasional, {len(benign_clients)} Benign Clients, "
          f"{len(target_servers)} Target Servers.")

    start_time = datetime(2026, 8, 26, 10, 0, 0)
    chunk_report = max(10000, num_rows // 10)

    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()

        for i in range(num_rows):
            writer.writerow(generate_flow(
                start_time, persistent_attackers, occasional_attackers, benign_clients, target_servers
            ))
            # advance time by 10ms to 200ms
            start_time += timedelta(milliseconds=random.randint(10, 200))

            if (i + 1) % chunk_report == 0:
                print(f"  [OK] Generated {i + 1:,} / {num_rows:,} records...")

    print("=" * 65)
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    print(f"[SUCCESS] Generated {num_rows:,} rows -> {file_path} ({file_size_mb:.2f} MB)")
    print("=" * 65)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate synthetic CICIDS2017 security logs.")
    parser.add_argument("--rows", type=int, default=100000, help="Number of records to generate (default: 100000 / 1 Lakh)")
    parser.add_argument("--out", type=str, default=None, help="Output CSV path")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    sample_file = Path(args.out) if args.out else (base_dir / 'data' / 'raw' / 'sample_cicids2017.csv')
    generate_sample(sample_file, args.rows)
