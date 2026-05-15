"""
model_trainer.py - Training classification models (XGBoost) for threat detection.
"""
import os
import logging
import joblib
from xgboost import XGBClassifier

log = logging.getLogger("TRAINER")

def train_xgboost(X_train, y_train):
    log.info("Training XGBoost classifier...")
    # Using small params for speed in this dev env
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        use_label_encoder=False,
        eval_metric='mlogloss'
    )
    model.fit(X_train, y_train)
    
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/xgb_model.pkl")
    log.info("Model saved to models/xgb_model.pkl")
    return model
