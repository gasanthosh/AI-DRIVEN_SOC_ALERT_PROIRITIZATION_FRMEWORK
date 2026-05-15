"""
data_pipeline.py - Data cleaning, feature engineering, and preprocessing.
Supports both training and real-time inference.
"""

import os
import logging
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

# -- Logging ------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("DATA_PIPELINE")

# -- Sniffer-Compatible Feature Set -------------------------------------------
# These 8 features are easily extractable from real-time network packets.
SNIFFER_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean"
]

def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Core cleaning logic used for both training and inference.
    1. Strip column names
    2. Handle missing/inf values
    3. Drop irrelevant columns
    """
    df = df.copy()
    df.columns = df.columns.str.strip()
    
    # Handle infinite and NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Numeric columns only for imputation
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(0)
    
    # Drop known metadata or non-feature columns if they exist
    to_drop = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]
    df = df.drop(columns=[c for c in to_drop if c in df.columns], errors="ignore")
    
    return df

def load_data(file_path: str) -> pd.DataFrame:
    log.info(f"Loading data from {file_path}")
    df = pd.read_csv(file_path, low_memory=False)
    return df

def process_data(data_dir: str, use_sniffer_features: bool = False):
    """
    Main pipeline: Load all CSVs, clean, scale, and save artifacts.
    """
    all_files = [os.path.join(data_dir, f) for f in os.listdir(data_dir) if f.endswith(".csv")]
    dfs = []
    for f in all_files:
        dfs.append(load_data(f))
    
    df = pd.concat(dfs, ignore_index=True)
    log.info(f"Combined dataset: {df.shape}")
    
    # Strip spaces now to ensure filtering works
    df.columns = df.columns.str.strip()

    if use_sniffer_features:
        log.info(f"Filtering to sniffer-compatible feature set: {SNIFFER_FEATURES}")
        df = df[SNIFFER_FEATURES + ["Label"]]

    # Pre-clean
    df = clean_features(df)
    
    # Label encoding
    if "Label" not in df.columns:
        raise ValueError("Dataset must contain a 'Label' column for training.")
    
    # Filter out rare classes (< 2 samples) to allow stratified split
    counts = df["Label"].value_counts()
    rare_classes = counts[counts < 2].index
    if len(rare_classes) > 0:
        log.info(f"Filtering rare classes: {list(rare_classes)}")
        df = df[~df["Label"].isin(rare_classes)]

    le = LabelEncoder()
    y = le.fit_transform(df["Label"])
    X = df.drop(columns=["Label"])
    
    # Feature names
    feature_names = X.columns.tolist()
    
    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Save artifacts
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, "models/scaler.pkl")
    joblib.dump(le, "models/label_encoder.pkl")
    joblib.dump(feature_names, "models/feature_names.pkl")
    
    log.info("Pipeline artifacts saved to models/")
    return X_train, X_test, y_train, y_test

if __name__ == "__main__":
    # Example usage
    DATA_DIR = "d:/soc/cic_ids_2017"
    if os.path.exists(DATA_DIR):
        process_data(DATA_DIR)
