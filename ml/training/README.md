# ML Model Training Module

Contains PySpark MLlib model training and evaluation routines:
- `train_models.py`: Splits feature data into 80/20 train/test sets, trains DecisionTree and RandomForest classifiers, evaluates classification benchmarks, and serializes the best model artifact to `ml/models/rf_threat_model`.
- `evaluate_models.py`: Computes detailed multi-class confusion matrix and per-class precision/recall metrics.

## Execution
```bash
python ml/training/train_models.py
```
