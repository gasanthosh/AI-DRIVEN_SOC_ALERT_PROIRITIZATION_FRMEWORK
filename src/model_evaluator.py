"""
model_evaluator.py - Performance assessment using accuracy, precision, recall, and confusion matrix.
"""
import os
import logging
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

log = logging.getLogger("EVALUATOR")

def evaluate_model(model, X_test, y_test, le):
    log.info("Evaluating model performance...")
    y_pred = model.predict(X_test)
    
    # Reports
    report = classification_report(y_test, y_pred, target_names=le.classes_)
    log.info("\n" + report)
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(12, 10))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=le.classes_, yticklabels=le.classes_)
    plt.title("Confusion Matrix")
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    
    os.makedirs("reports", exist_ok=True)
    plt.savefig("reports/confusion_matrix.png")
    with open("reports/classification_report.txt", "w") as f:
        f.write(report)
    log.info("Evaluation artifacts saved to reports/")
