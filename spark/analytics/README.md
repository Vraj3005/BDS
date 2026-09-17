# Spark Analytics Module

Contains analytical aggregations:
- `attack_statistics.py`: Counts and percentages per attack type (DDoS, PortScan, Botnet, etc.).
- `ip_analysis.py`: Aggregates attack volume by source and destination IPs.
- `timeline_analysis.py`: Groups security events by hour/day buckets to identify peak intrusion periods.
