# Threat Intelligence & Risk Scoring Engine

Calculates composite 0–100 Threat Reputation Risk Scores and profiles malicious IP actors:
- `calculate_risk.py`: Aggregates multi-dimensional threat signals (attack frequency, severity weights, and target destination dispersion), computes dynamic risk scores between 0 and 100, assigns security action tiers, and exports intelligence profiles to Parquet and MongoDB.

## Scoring Methodology
- **Attack Frequency Score**: Up to 40 points based on flow volume.
- **Severity Multiplier**: Up to 40 points (DDoS=40, Botnet=30, BruteForce=25, PortScan=15).
- **Target Dispersion Score**: Up to 20 points based on the number of unique destination targets attacked.

## Risk Categories
| Score | Threat Tier | Recommended Action |
| :--- | :--- | :--- |
| `0 - 25` | **Low** | Standard Network Monitoring |
| `26 - 50` | **Medium** | Rate-limit & Deep Inspection |
| `51 - 75` | **High** | Active Firewall Throttle |
| `76 - 100` | **Critical** | Auto-Block & Quarantine |

## Execution
```bash
# Calculate scores for all IP addresses
python ml/risk_engine/calculate_risk.py

# Query intelligence profile for a specific IP
python ml/risk_engine/calculate_risk.py --ip 192.168.1.5

# Calculate and export scores to MongoDB Atlas
python ml/risk_engine/calculate_risk.py --mongo
```
