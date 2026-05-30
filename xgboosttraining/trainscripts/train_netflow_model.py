"""
XGBoost Training Script for NetFlow V2 Botnet/Attack Detection
======================================================================
Trains an XGBClassifier on the 39 NetFlow V2 behavioral features.
Optimized for memory efficiency to handle massive multi-GB CSV datasets.

Features precise:
1. Binary mapping: 'BENIGN'/'0'/'0.0' -> 0 (Normal), All others -> 1 (Attack)
2. Column schema alignment to match Go's model inference order
3. Memory optimizations: PyArrow engine, selective loading, downcasting, custom downsampling
4. XGBoost JSON-compatible model export for Go inference
"""

import os
import glob
import gc
import sys
import warnings
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Suppress verbose casting and future warnings
warnings.filterwarnings('ignore', category=RuntimeWarning)
warnings.filterwarnings('ignore', category=FutureWarning)

def main():
    print("=" * 70)
    print("     XGBoost NetFlow V2 Detection Model Training Pipeline      ")
    print("=" * 70)

    # 1. DEFINE EXACT SCHEMA OF 39 FEATURES
    feature_cols = [
        'PROTOCOL',                     # f0
        'L7_PROTO',                     # f1
        'IN_BYTES',                     # f2
        'OUT_BYTES',                    # f3
        'IN_PKTS',                      # f4
        'OUT_PKTS',                     # f5
        'FLOW_DURATION_MILLISECONDS',   # f6
        'TCP_FLAGS',                    # f7
        'CLIENT_TCP_FLAGS',             # f8
        'SERVER_TCP_FLAGS',             # f9
        'DURATION_IN',                  # f10
        'DURATION_OUT',                 # f11
        'MIN_TTL',                      # f12
        'MAX_TTL',                      # f13
        'LONGEST_FLOW_PKT',             # f14
        'SHORTEST_FLOW_PKT',            # f15
        'MIN_IP_PKT_LEN',               # f16
        'MAX_IP_PKT_LEN',               # f17
        'SRC_TO_DST_SECOND_BYTES',      # f18
        'DST_TO_SRC_SECOND_BYTES',      # f19
        'RETRANSMITTED_IN_BYTES',       # f20
        'RETRANSMITTED_IN_PKTS',        # f21
        'RETRANSMITTED_OUT_BYTES',      # f22
        'RETRANSMITTED_OUT_PKTS',       # f23
        'SRC_TO_DST_AVG_THROUGHPUT',    # f24
        'DST_TO_SRC_AVG_THROUGHPUT',    # f25
        'NUM_PKTS_UP_TO_128_BYTES',     # f26
        'NUM_PKTS_128_TO_256_BYTES',    # f27
        'NUM_PKTS_256_TO_512_BYTES',    # f28
        'NUM_PKTS_512_TO_1024_BYTES',   # f29
        'NUM_PKTS_1024_TO_1514_BYTES',  # f30
        'TCP_WIN_MAX_IN',               # f31
        'TCP_WIN_MAX_OUT',              # f32
        'ICMP_TYPE',                    # f33
        'ICMP_IPV4_TYPE',               # f34
        'DNS_QUERY_ID',                 # f35
        'DNS_QUERY_TYPE',               # f36
        'DNS_TTL_ANSWER',               # f37
        'FTP_COMMAND_RET_CODE'          # f38
    ]

    # 2. LOCATE CSV DATAFILES
    script_dir = os.path.dirname(os.path.realpath(__file__))
    search_paths = [
        os.path.join(script_dir, "..", "netflow_csv", "*.csv"),
        os.path.join(script_dir, "netflow_csv", "*.csv"),
        os.path.join(".", "xgboosttraining", "netflow_csv", "*.csv"),
        os.path.join(".", "netflow_csv", "*.csv"),
        os.path.join("..", "netflow_csv", "*.csv")
    ]
    
    csv_files = []
    for pattern in search_paths:
        matches = glob.glob(pattern)
        if matches:
            # Filter out NetFlow_v2_Features.csv from the data files list
            matches = [m for m in matches if "NetFlow_v2_Features.csv" not in os.path.basename(m)]
            if matches:
                csv_files = sorted(matches)
                break

    if not csv_files:
        print("ERROR: Could not locate the netflow_csv directory or NetFlow CSV files.")
        print("Expected locations searched:")
        for p in search_paths:
            print(f"  - {os.path.abspath(p)}")
        sys.exit(1)

    print(f"Located {len(csv_files)} data CSV files in {os.path.dirname(csv_files[0])}")

    # 3. LOAD DATASETS INCREMENTALLY WITH MEMORY OPTIMIZATIONS
    dfs = []
    total_rows = 0
    unique_raw_labels = set()
    mapped_counts = {0: 0, 1: 0} # 0: Benign, 1: Attack

    print("\nLoading and preprocessing dataset...")
    # Use only columns we need to save parsing time and memory overhead
    columns_to_load = feature_cols + ['Label']

    # Use a chunk size of 1 Million rows to prevent MemoryError / Overflow during parsing
    chunk_size = 1000000

    for i, path in enumerate(csv_files):
        filename = os.path.basename(path)
        print(f"[{i+1}/{len(csv_files)}] Reading {filename} in chunks of {chunk_size:,} rows...")
        
        try:
            # We read in chunks to keep peak memory extremely low
            # Optimize: Load with pyarrow engine which is faster and uses less memory
            try:
                chunks = pd.read_csv(path, usecols=columns_to_load, chunksize=chunk_size, engine='pyarrow')
            except (ValueError, ImportError, TypeError):
                chunks = pd.read_csv(path, usecols=columns_to_load, chunksize=chunk_size)
                
            for chunk_idx, chunk in enumerate(chunks):
                chunk.columns = chunk.columns.str.strip()
                
                # Drop rows with null/missing labels to keep data clean
                chunk = chunk.dropna(subset=['Label'])
                
                # Capture raw labels for precise reporting
                for raw_lbl in chunk['Label'].unique():
                    unique_raw_labels.add(raw_lbl)
                    
                # ABSOLUTE PRECISION: Strip whitespace and convert to uppercase/string for mapping
                clean_labels = chunk['Label'].astype(str).str.strip().str.upper()
                
                # Map 'BENIGN', '0', '0.0' to 0, anything else to 1 (Attack)
                is_attack = np.where((clean_labels == 'BENIGN') | (clean_labels == '0') | (clean_labels == '0.0'), 0, 1).astype(np.int8)
                chunk['is_attack'] = is_attack
                
                # Record mapped counts
                mapped_counts[0] += int((is_attack == 0).sum())
                mapped_counts[1] += int((is_attack == 1).sum())
                
                # Downcast all features to float32 to reduce memory footprint by 50%
                for col in feature_cols:
                    if chunk[col].dtype == object:
                        # Clean up any unexpected strings/errors by converting coercively to float32
                        chunk[col] = pd.to_numeric(chunk[col], errors='coerce').astype(np.float32)
                    else:
                        chunk[col] = chunk[col].astype(np.float32)
                    
                # Keep only the features in exact schema order and the target column
                chunk = chunk[feature_cols + ['is_attack']]
                
                dfs.append(chunk)
                total_rows += len(chunk)
                
                # Print progress for very large files
                if (chunk_idx + 1) % 5 == 0:
                    print(f"  Processed {(chunk_idx + 1) * chunk_size:,} rows...")
                
                # Clean up references and run garbage collector
                del chunk
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
        lbl_str = str(lbl).strip().upper()
        mapped_val = 0 if lbl_str in ['BENIGN', '0', '0.0'] else 1
        mapping_str = "0 (Normal/BENIGN)" if mapped_val == 0 else "1 (Attack/Anomaly)"
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
    local_model_path = 'botnet_xgboost.json'
    print(f"\nExporting model booster to '{local_model_path}' in JSON format...")
    model.get_booster().dump_model(local_model_path, dump_format='json')
    print("Model booster exported successfully.")

    # Also automatically copy/export to GoVersionML's Xgboost folder if it exists
    go_xgboost_dir = os.path.abspath(os.path.join(script_dir, "..", "..", "GoVersionML", "Xgboost"))
    if os.path.exists(go_xgboost_dir):
        target_path = os.path.join(go_xgboost_dir, "botnet_xgboost.json")
        print(f"Go ML codebase located! Copying model to {target_path}...")
        try:
            model.get_booster().dump_model(target_path, dump_format='json')
            print("Successfully updated model in Go ML workspace.")
        except Exception as e:
            print(f"Failed to copy model to Go workspace: {e}")
    else:
        print("Could not automatically locate GoVersionML/Xgboost directory. Please copy the generated 'botnet_xgboost.json' file manually.")

    print("\nPipeline complete! The model is ready for Go streaming detection.")

if __name__ == "__main__":
    main()
