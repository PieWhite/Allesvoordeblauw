"""
XGBoost Training Script for Botnet Detection
============================================
Trains an XGBClassifier on our extracted behavioral features.
Critical parameters handled:
- class imbalance scaling (`scale_pos_weight`)
- AUCPR evaluation metric (optimal for highly skewed data)
- Stratified 80/20 train/test split.
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.metrics import classification_report, confusion_matrix

def main():
    print("Loading Master Dataset V3 (5.5 Million Rows)...")
    # Point directly to the newly merged Binetflowdata file
    df = pd.read_csv(r"..\Binetflowdata\master_features_v3_FINAL.csv")
    print(f"Loaded {len(df):,} rows.")

    # These match exactly the V2 columns our new extract script generated
    feature_cols = [
        'flow_count', 'unique_dst_ips', 'unique_dst_ports', 
        'total_bytes', 'total_packets', 'avg_bytes_per_flow', 'avg_packets_per_flow',
        'pct_tcp', 'pct_udp', 'pct_icmp',
        'pct_well_known_ports', 'pct_high_ports',
        'avg_duration', 'iat_mean', 'iat_variance',
        'port_symmetry', 'ip_port_ratio', 'avg_payload_per_packet',
        'pct_syn_only', 'pct_rst', 'iat_cv'
    ]

    # Validate all required columns exist
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in CSV: {missing}")

    X = df[feature_cols]
    
    # IMPORTANT: xgboost-go expects feature names to be 'f0', 'f1', etc. 
    # so we must rename the columns before splitting and training.
    X.columns = [f"f{i}" for i in range(len(feature_cols))]
    
    y = df['is_botnet']
    
    if 'src4_addr' not in df.columns:
        raise ValueError("Missing 'src4_addr' column needed for Grouped split!")
    groups = df['src4_addr']

    print("Splitting data into 80% train / 20% test (Stratified by Label, Grouped by IP)...")
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    
    # We just need one split of 80/20
    train_idx, test_idx = next(sgkf.split(X, y, groups))
    
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    # Save the Test Set IPs so we can extract raw JSON for the Go inference engine later
    test_ips = df.iloc[test_idx]['src4_addr'].unique()
    pd.Series(test_ips).to_csv('test_set_ips.txt', index=False, header=False)
    print(f"\nSaved {len(test_ips)} unique isolated Test IPs to 'test_set_ips.txt'")

    # 1. THE IMBALANCE FIX (scale_pos_weight)
    botnet_count = y_train.sum()
    normal_count = len(y_train) - botnet_count
    
    scale_weight = normal_count / botnet_count if botnet_count > 0 else 1.0
    print(f"Training Dataset -> Normal: {normal_count:,} | Botnet: {botnet_count:,}")
    print(f"Applying scale_pos_weight = {scale_weight:.2f}")

    # 2. THE XGBOOST MODEL
    print("Initializing XGBoost...")
    model = xgb.XGBClassifier(
        n_estimators=200,          # Build 200 decision trees
        learning_rate=0.1,         # Standard step size
        max_depth=6,               # Deep enough to find complex interactions between features
        scale_pos_weight=scale_weight, # Force model to care about the 0.02% botnet traffic
        eval_metric='aucpr',       # Area Under Precision-Recall Curve (best for imbalanced data)
        random_state=42,
        n_jobs=-1                  # Use all available CPU cores
    )

    print("Training model... (This will take a moment)")
    model.fit(X_train, y_train)

    # 3. EVALUATION
    print("\n--- Training Complete! Evaluating Model ---")
    y_pred = model.predict(X_test)

    print("\nConfusion Matrix (Test Set):")
    # Format: 
    # [True Negatives  , False Positives]
    # [False Negatives , True Positives]
    print(confusion_matrix(y_test, y_pred))

    print("\nClassification Report (Precision & Recall):")
    print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Botnet (1)'], digits=4))

    # 4. EXPLAINABILITY (Feature Importance)
    importance = model.feature_importances_
    feat_imp = pd.DataFrame({'Feature': feature_cols, 'Importance': importance})
    feat_imp = feat_imp.sort_values(by='Importance', ascending=False)
    
    print("\nTop 10 Most Important Features (What the model looks for):")
    print(feat_imp.head(10).to_string(index=False))

    # 5. EXPORT FOR GO (Using dump_model for xgboost-go JSON compatibility)
    model_path = 'botnet_xgboost.json'
    # The xgboost-go library requires the exact output from the original dump_model API
    model.get_booster().dump_model(model_path, dump_format='json')
    print(f"\nModel mathematically saved to '{model_path}' ready for Go inference.")

if __name__ == "__main__":
    main()
