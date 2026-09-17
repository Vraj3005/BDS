# Machine Learning & Threat Intelligence Module

Responsible for automated attack classification and risk scoring using PySpark MLlib.

## Responsibilities (Lead: Member 3)
- Phase 8: ML model training (Decision Tree, Random Forest) on network flow features
- Phase 8: Attack prediction and model evaluation (Accuracy, F1-score, Confusion Matrix)
- Phase 9: Threat Intelligence & IP Risk Scoring engine (0-100 score based on attack volume, severity, destination scope)

## Directory Structure
- `training/`: Spark MLlib training pipelines (`train_classifier.py`).
- `models/`: Saved model binaries and pipeline stages (`.parquet` / spark model formats).
- `prediction/`: Inference scripts (`predict_threat.py`) calculating predicted label and confidence.
- `risk_engine/`: Threat intelligence scoring formula and reputation tracker (`calculate_risk.py`).
