# Threat Intelligence & Risk Engine

Calculates an aggregated risk score (0-100) and severity rating for IP addresses.

## Scoring Methodology
- **Attack Volume**: Frequency of attacks originating from the IP.
- **Severity Multiplier**: Weight assigned to attack type (e.g. DDoS=40, Botnet=35, BruteForce=20).
- **Target Dispersion**: Number of unique destination targets attacked.
- **Activity Recency**: Decay or escalation factor based on event timestamps.

## Risk Categories
| Score | Level | Action |
| :--- | :--- | :--- |
| `0 - 25` | Low | Monitor |
| `26 - 50` | Medium | Throttle |
| `51 - 75` | High | Investigate |
| `76 - 100` | Critical | Auto-Block / Quarantine |
