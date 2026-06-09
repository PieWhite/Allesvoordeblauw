"""
XGBoost Training Script for PCAP Botnet/Attack Detection (CICIoT2023)
======================================================================
Trains an XGBClassifier on the 39 statistical features extracted from PCAP data.
Optimized for memory efficiency to handle a ~9 GB CSV dataset.

Features precise:
1. Binary mapping: 'BENIGN' -> 0 (Normal), All others -> 1 (Attack)
2. Column schema alignment to match Go's `ToPcapMLVector()` order
3. Memory optimizations: PyArrow engine, selective loading, downcasting
4. XGBoost JSON-compatible model export for Go inference
"""

import os
import glob
import gc
import sys
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

def main():
    print("=" * 70)
    print("      XGBoost PCAP Detection Model Training Pipeline (CICIoT2023)      ")
    print("=" * 70)

    # 1. DEFINE EXACT SCHEMA ALIGNMENT WITH GO ToPcapMLVector()
    feature_cols = [
        'Header_Length',       # f0
        'Time_To_Live',        # f1
        'Rate',                # f2
        'fin_flag_number',     # f3
        'syn_flag_number',     # f4
        'rst_flag_number',     # f5
        'psh_flag_number',     # f6
        'ack_flag_number',     # f7
        'ece_flag_number',     # f8
        'cwr_flag_number',     # f9
        'syn_count',           # f10
        'ack_count',           # f11
        'fin_count',           # f12
        'rst_count',           # f13
        'IGMP',                # f14
        'HTTPS',               # f15
        'HTTP',                # f16
        'Telnet',              # f17
        'DNS',                 # f18
        'SMTP',                # f19
        'SSH',                 # f20
        'IRC',                 # f21
        'TCP',                 # f22
        'UDP',                 # f23
        'DHCP',                # f24
        'ARP',                 # f25
        'ICMP',                # f26
        'IPv',                 # f27
        'LLC',                 # f28
        'Tot sum',             # f29
        'Min',                 # f30
        'Max',                 # f31
        'AVG',                 # f32
        'Std',                 # f33
        'Tot size',            # f34
        'IAT',                 # f35
        'Number',              # f36
        'Variance',            # f37
        'Protocol Type'        # f38
    ]

    # 2. LOCATE CSV DATAFILES
    # Try multiple search directories to handle running from different context locations
    script_dir = os.path.dirname(os.path.realpath(__file__))
    search_paths = [
        os.path.join(script_dir, "..", "MERGED_CSV (1)", "MERGED_CSV", "*.csv"),
        os.path.join(script_dir, "MERGED_CSV (1)", "MERGED_CSV", "*.csv"),
        os.path.join(".", "MERGED_CSV (1)", "MERGED_CSV", "*.csv"),
        os.path.join("..", "MERGED_CSV (1)", "MERGED_CSV", "*.csv")
    ]
    
    csv_files = []
    for pattern in search_paths:
        matches = glob.glob(pattern)
        if matches:
            csv_files = sorted(matches)
            break

    if not csv_files:
        print("ERROR: Could not locate the MERGED_CSV directory or CSV files.")
        print("Expected locations searched:")
        for p in search_paths:
            print(f"  - {os.path.abspath(p)}")
        sys.exit(1)

    print(f"Located {len(csv_files)} CSV files in {os.path.dirname(csv_files[0])}")

    # OPTIONAL: Allow subsetting files for fast/limited-RAM testing
    # e.g., set environment variable LIMIT_FILES=5 to train on a smaller portion
    limit_env = os.environ.get("LIMIT_FILES")
    if limit_env:
        try:
            limit = int(limit_env)
            csv_files = csv_files[:limit]
            print(f"--> LIMIT_FILES active! Restricted to first {limit} files.")
        except ValueError:
            pass

    # 3. LOAD DATASETS INCREMENTALLY WITH MEMORY OPTIMIZATIONS
    dfs = []
    total_rows = 0
    unique_raw_labels = set()
    mapped_counts = {0: 0, 1: 0} # 0: Benign, 1: Attack

    print("\nLoading and preprocessing dataset...")
    # Use only columns we need to save parsing time and memory overhead
    columns_to_load = feature_cols + ['Label']

    for i, path in enumerate(csv_files):
        filename = os.path.basename(path)
        print(f"[{i+1}/{len(csv_files)}] Reading {filename}...")
        
        try:
            # Optimize: Load with pyarrow engine which is faster and uses less memory
            df_chunk = pd.read_csv(path, usecols=columns_to_load, engine='pyarrow')
            df_chunk.columns = df_chunk.columns.str.strip()
            
            # Drop rows with null/missing labels to keep data clean
            df_chunk = df_chunk.dropna(subset=['Label'])
            
            # Capture raw labels for precise reporting
            for raw_lbl in df_chunk['Label'].unique():
                unique_raw_labels.add(raw_lbl)
                
            # ABSOLUTE PRECISION: Strip whitespace and convert to uppercase for mapping
            clean_labels = df_chunk['Label'].astype(str).str.strip().str.upper()
            
            # Map 'BENIGN' to 0, anything else to 1 (Attack)
            is_attack = np.where(clean_labels == 'BENIGN', 0, 1).astype(np.int8)
            df_chunk['is_attack'] = is_attack
            
            # Record mapped counts
            mapped_counts[0] += int((is_attack == 0).sum())
            mapped_counts[1] += int((is_attack == 1).sum())
            
            # Downcast all features to float32 to reduce memory footprint by 50%
            for col in feature_cols:
                df_chunk[col] = df_chunk[col].astype(np.float32)
                
            # Keep only the features in exact Go schema order and the target column
            df_chunk = df_chunk[feature_cols + ['is_attack']]
            
            dfs.append(df_chunk)
            total_rows += len(df_chunk)
            
            # Clean up references and run garbage collector
            del df_chunk
            gc.collect()
            
        except Exception as e:
            print(f"  WARNING: Failed to parse {filename}: {e}")

    if not dfs:
        print("ERROR: No data loaded successfully!")
        sys.exit(1)

    print(f"\nConcatenating {len(dfs)} data chunks in memory...")
    df = pd.concat(dfs, ignore_index=True)
    dfs = None # free reference
    gc.collect()
    print(f"Master Dataset size in memory: {df.memory_usage(deep=True).sum() / (1024**2):.2f} MB")
    print(f"Total records loaded: {len(df):,}")

    # 4. PRECISION LABEL VERIFICATION REPORT
    print("\n" + "=" * 50)
    print("           PRECISION LABEL MAPPING REPORT           ")
    print("=" * 50)
    print(f"Total BENIGN rows (Class 0): {mapped_counts[0]:,}")
    print(f"Total ATTACK rows (Class 1): {mapped_counts[1]:,}")
    print(f"Total distinct raw labels processed ({len(unique_raw_labels)}):")
    for lbl in sorted(list(unique_raw_labels)):
        mapped_val = 0 if lbl.strip().upper() == 'BENIGN' else 1
        mapping_str = "0 (Normal/BENIGN)" if mapped_val == 0 else "1 (Attack/Botnet)"
        print(f"  - '{lbl}' -> Mapped precisely to: {mapping_str}")
    print("=" * 50)

    # 5. PREPARE TRAINING ARRAYS AND RENAME COLUMNS FOR GO
    print("\nPreparing training vectors...")
    X = df[feature_cols]
    y = df['is_attack']
    
    # Clean up infinite values by replacing them with NaN (which XGBoost handles natively)
    X = X.replace([np.inf, -np.inf], np.nan)
    
    # IMPORTANT: xgboost-go expects feature names to be f0, f1, etc.
    # so we must rename the columns before splitting and training.
    X.columns = [f"f{i}" for i in range(len(feature_cols))]

    # 6. STRATIFIED SPLIT
    print("Splitting into 80% train / 20% test (Stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Free memory of Master dataframe since we have splits now
    df = None
    gc.collect()

    # 7. COMPUTE scale_pos_weight TO RESOLVE CLASS IMBALANCE
    attack_count = y_train.sum()
    normal_count = len(y_train) - attack_count
    
    # Calculate pos weight: normal/attack
    scale_weight = normal_count / attack_count if attack_count > 0 else 1.0
    print(f"\nTraining set balance -> Normal (0): {normal_count:,} | Attack (1): {attack_count:,}")
    print(f"Calculated scale_pos_weight = {scale_weight:.4f}")

    # 8. TRAIN THE XGBOOST MODEL
    print("\nInitializing XGBoost Classifier...")
    model = xgb.XGBClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=6,
        scale_pos_weight=scale_weight,
        eval_metric='aucpr', # Best metric for imbalanced validation
        random_state=42,
        n_jobs=-1
    )

    print("Training XGBoost model... (This may take a moment)")
    model.fit(X_train, y_train)
    print("Training complete!")

    # 9. MODEL EVALUATION
    print("\n" + "=" * 50)
    print("                  EVALUATION METRICS                ")
    print("=" * 50)
    y_pred = model.predict(X_test)
    
    print("\nConfusion Matrix (Test Set):")
    # [True Negatives  , False Positives]
    # [False Negatives , True Positives]
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Attack (1)'], digits=5))

    # Explainability (Feature Importance)
    importance = model.feature_importances_
    feat_imp = pd.DataFrame({'Feature': feature_cols, 'Importance': importance})
    feat_imp = feat_imp.sort_values(by='Importance', ascending=False)
    print("\nTop 15 Most Influential Features:")
    print(feat_imp.head(15).to_string(index=False))
    print("=" * 50)

    # 10. EXPORT MATHEMATICAL MODEL TO JSON FOR GO INFERENCE
    # Write to local directory first
    local_model_path = 'pcap_xgboost.json'
    print(f"\nExporting model booster to '{local_model_path}' in JSON format...")
    model.get_booster().dump_model(local_model_path, dump_format='json')
    print("Model booster exported successfully.")

    # Also automatically copy/export to GoVersionML's Xgboost folder if it exists
    go_xgboost_dir = os.path.abspath(os.path.join(script_dir, "..", "..", "GoVersionML", "Xgboost"))
    if os.path.exists(go_xgboost_dir):
        target_path = os.path.join(go_xgboost_dir, "pcap_xgboost.json")
        print(f"Go ML codebase located! Copying model to {target_path}...")
        try:
            model.get_booster().dump_model(target_path, dump_format='json')
            print("Successfully updated model in Go ML workspace.")
        except Exception as e:
            print(f"Failed to copy model to Go workspace: {e}")
    else:
        print("Could not automatically locate GoVersionML/Xgboost directory. Please copy the generated 'pcap_xgboost.json' file manually.")

    print("\nPipeline complete! The model is ready for Go streaming detection.")

if __name__ == "__main__":
    main()
