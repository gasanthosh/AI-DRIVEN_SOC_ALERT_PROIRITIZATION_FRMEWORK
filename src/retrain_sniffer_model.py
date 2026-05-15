"""
retrain_sniffer_model.py - Ad-hoc script to retrain on 8 sniffer features.
"""
import os
import logging
from data_pipeline import process_data
from model_trainer import train_xgboost
from model_evaluator import evaluate_model
import joblib

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("RETRAIN")

def main():
    DATA_DIR = "d:/soc/cic_ids_2017"
    if not os.path.exists(DATA_DIR):
        log.error(f"Data directory {DATA_DIR} not found.")
        return

    # 1. Process data with sniffer features only
    log.info("Starting data pipeline (SNIFFER FEATURES ONLY)...")
    X_train, X_test, y_train, y_test = process_data(DATA_DIR, use_sniffer_features=True)

    # 2. Train model
    model = train_xgboost(X_train, y_train)

    # 3. Evaluate
    le = joblib.load("models/label_encoder.pkl")
    evaluate_model(model, X_test, y_test, le)
    
    log.info("Retraining complete. 8-feature model saved to models/xgb_model.pkl")

if __name__ == "__main__":
    main()
