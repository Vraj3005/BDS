# Threat Prediction Module

Contains inference routines for cyber attack classification:
- `predict_threat.py`: Loads the trained Random Forest model and `label_mapping.json`, computes dynamic prediction confidence from probability vectors, outputs threat alerts with severity tiers (`Low`, `Medium`, `High`, `Critical`), and optionally streams predictions into MongoDB.

## Execution
```bash
# Predict on sample batch
python ml/prediction/predict_threat.py --limit 10

# Predict and persist to MongoDB Atlas
python ml/prediction/predict_threat.py --limit 20 --mongo
```
