# Data Directory

This directory holds raw security datasets, synthetic development samples, and processed artifacts.

## Subdirectories

- `raw/`: Raw CSV files (e.g. CICIDS2017 dataset slices or generated samples).
  - Note: Heavy multi-GB raw CSV files are excluded from Git via `.gitignore`.
  - `sample_cicids2017.csv` is maintained for rapid offline testing and CI.
- `processed/`: Cleaned and transformed datasets (e.g. Parquet files output by Spark ETL jobs).

## Dataset: CICIDS2017 Format

Expected features:
| Column | Description | Example |
| :--- | :--- | :--- |
| `timestamp` | Date and time of network event | `2026-08-26 10:30:22` |
| `source_ip` | Originating IP address | `192.168.10.15` |
| `destination_ip` | Target IP address | `10.0.0.5` |
| `protocol` | Transport layer protocol | `TCP`, `UDP`, `ICMP` |
| `flow_duration` | Duration of flow in microseconds | `120000` |
| `packet_length` | Average or total packet size | `4500` |
| `total_bytes` | Total bytes transferred | `18500` |
| `packet_count` | Number of packets in flow | `32` |
| `attack_type` | Security classification | `BENIGN`, `DDoS`, `PortScan`, `Botnet`, `BruteForce` |
| `severity` | Threat severity level | `Low`, `Medium`, `High`, `Critical` |
