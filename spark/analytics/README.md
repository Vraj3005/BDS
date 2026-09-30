# Spark Analytics Module — Phase 7

Distributed attack-pattern and timeline analytics over cleaned CICIDS2017 network logs.

## Files

| File | Description |
|------|-------------|
| `attack_statistics.py` | Per-attack-type distribution, protocol breakdown, hourly intensity, severity distribution |
| `ip_timeline_analysis.py` | Top attacking/targeted IPs, IP×Attack cross-tab, hourly/daily timeline, 6-hour surge windows |

## Aggregations Produced

### Attack Statistics (`attack_statistics.py`)
| Output Parquet | Description |
|---|---|
| `attack_distribution.parquet` | Count + % share per attack type (DDoS, PortScan, Botnet, etc.) |
| `protocol_distribution.parquet` | TCP/UDP/ICMP split with attack vs benign breakdown |
| `hourly_attack_intensity.parquet` | Attack count per hour (0–23) with attack-rate % |
| `severity_distribution.parquet` | Critical / High / Medium / Low level counts |
| `attack_stats_summary.json` | JSON run summary |

### IP Threat Frequency (`ip_timeline_analysis.py --mode ip`)
| Output Parquet | Description |
|---|---|
| `top_attacking_ips.parquet` | Top 50 source IPs ranked by attack-flow count |
| `top_targeted_ips.parquet` | Top 50 victim destination IPs |
| `ip_attack_crosstab.parquet` | Attack-type pivot table for top 20 IPs |

### Network Timeline (`ip_timeline_analysis.py --mode timeline`)
| Output Parquet | Description |
|---|---|
| `network_timeline_hourly.parquet` | 24-hour attack vs benign traffic timeline |
| `network_timeline_daily.parquet` | Day-of-week attack cadence |
| `attack_surge_windows.parquet` | 6-hour surge window ranking (00-05, 06-11, 12-17, 18-23) |

## Running

```bash
# Full Phase 7 pipeline (recommended)
python spark/jobs/run_analytics_pipeline.py

# Individual jobs
python spark/analytics/attack_statistics.py
python spark/analytics/ip_timeline_analysis.py --mode ip
python spark/analytics/ip_timeline_analysis.py --mode timeline

# Tests
python -m unittest tests/test_phase7_analytics.py -v
```

## MongoDB Collections Updated
- `attack_stats` — attack type distribution
- `ip_threat_frequency` — top attacking IPs
- `timeline_stats` — hourly network timeline
