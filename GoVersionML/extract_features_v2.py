"""
ML Feature Extraction Pipeline V2 (Advanced)
============================================
Converts raw NetFlow JSON records into the V2 feature-engineered dataset for XGBoost.
Introduces 5 advanced features:
- Port Symmetry (P2P detection)
- Scan Ratios (target diversity vs target depth)
- Payload Deliver Ratio (bytes per packet)
- Error Percentages (SYN/RST)
- IAT Coefficient of Variation (Periodicity)
"""

import sys
import os
import json
import pandas as pd
import numpy as np
from datetime import datetime

# Optional: Disable SettingWithCopyWarning if it appears during pandas chaining
pd.options.mode.chained_assignment = None

def extract_features_v2(input_path, output_path, window_size='5min'):
    print(f"Loading JSON data from {input_path} (This may take a moment for large files)...")
    
    # Load JSON into pandas DataFrame
    df = pd.read_json(input_path)
    if len(df) == 0:
        print(f"File {input_path} is empty. Skipping.")
        return

    print(f"Loaded {len(df):,} flows. Processing V2 features...")

    # Ensure timestamps are parsed properly
    df['first'] = pd.to_datetime(df['first'], format='mixed', errors='coerce')
    df['last'] = pd.to_datetime(df['last'], format='mixed', errors='coerce')

    # Drop rows with invalid start times
    df = df.dropna(subset=['first'])

    # Bin the data into time windows (e.g., 5 minutes)
    df['time_window'] = df['first'].dt.floor(window_size)
    
    # --- CALCULATE PORT SYMMETRY ---
    print("Calculating P2P Port Symmetry Matrix...")
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)
    df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0)
    
    # Find unique (src_ip, port) pairs for outbound traffic
    df_out_ports = df[['src4_addr', 'time_window', 'dst_port']].drop_duplicates()
    
    # FIX: Find unique (dst_ip, port) pairs for inbound return traffic
    # We must look at the dst_port here too, because peers are connecting TO this port
    df_in_ports = df[['dst4_addr', 'time_window', 'dst_port']].drop_duplicates()
    
    # Rename inbound columns to perform an inner join/intersection
    df_in_ports = df_in_ports.rename(columns={'dst4_addr': 'src4_addr'})
    
    # Inner join matches instances where an IP acts as a client on Port X and a server on Port X
    sym_matches = pd.merge(df_out_ports, df_in_ports, on=['src4_addr', 'time_window', 'dst_port'], how='inner')
    symmetry_counts = sym_matches.groupby(['src4_addr', 'time_window']).size().reset_index(name='port_symmetry')
    # -------------------------------

    # Feature 1: Protocols
    df['is_tcp'] = (df['proto'] == 6).astype(int)
    df['is_udp'] = (df['proto'] == 17).astype(int)
    df['is_icmp'] = (df['proto'] == 1).astype(int)

    # Feature 2: TCP Flags
    df['tcp_flags'] = df['tcp_flags'].astype(str).fillna('')
    # Resilient SYN-only check: Has 'S' but no other terminating flags (Ack, Fin, Rst)
    df['syn_only'] = (
        df['tcp_flags'].str.contains('S') & 
        ~df['tcp_flags'].str.contains('A|F|R')
    ).astype(int)
    df['has_rst'] = df['tcp_flags'].str.contains('R').astype(int)

    # Feature 3: Port categories
    df['well_known_port'] = (df['dst_port'] < 1024).astype(int)

    # Feature 4: Flow duration in seconds
    df['duration_sec'] = (df['last'] - df['first']).dt.total_seconds().fillna(0).clip(lower=0)

    # Label (1 if Botnet, 0 otherwise)
    if 'label' in df.columns:
        df['label_str'] = df['label'].astype(str).str.lower()
        df['is_botnet_flow'] = df['label_str'].str.contains('botnet|bot').astype(int)
    else:
        df['is_botnet_flow'] = 0

    print("Optimizing memory and grouping by Target Flow...")
    
    # --- FIX: NetFlow v5 Beacon Hunter (Flow IAT instead of Packet IAT) ---
    # Bots don't just send packets; they robotically initiate entire connections.
    # We measure the StartTime gap between distinct flows originating from the 
    # same Source IP going to the exact same (DstIP, DstPort) pair.
    
    # Memory optimization: Free the pandas fragmented index
    df = df.sort_values(by=['src4_addr', 'dst4_addr', 'dst_port', 'first']).reset_index(drop=True)
    
    # Calculate Flow IAT (Time gap between connections to the same target)
    df['iat'] = df.groupby(['src4_addr', 'dst4_addr', 'dst_port', 'time_window'])['first'].diff().dt.total_seconds().fillna(0).astype('float32')

    # Aggregation mapping
    agg_funcs = {
        'first': 'count',                 # flow_count
        'dst4_addr': 'nunique',           # unique_dst_ips
        'dst_port': 'nunique',            # unique_dst_ports
        'in_bytes': 'sum',                # total_bytes
        'in_packets': 'sum',              # total_packets
        'is_tcp': 'sum',
        'is_udp': 'sum',
        'is_icmp': 'sum',
        'syn_only': 'sum',               
        'has_rst': 'sum',                
        'well_known_port': 'sum',
        'duration_sec': 'mean',           # avg_duration
        'iat': ['mean', 'var'],           # iat_mean, iat_variance
        'is_botnet_flow': 'max'           # 1 if any flow in window was botnet
    }

    grouped = df.groupby(['src4_addr', 'time_window']).agg(agg_funcs)

    # Flatten MultiIndex columns
    grouped.columns = ['_'.join(filter(None, col)).strip() for col in grouped.columns.values]
    grouped = grouped.reset_index()

    # Rename columns to clean, feature-ready names
    grouped = grouped.rename(columns={
        'first_count': 'flow_count',
        'dst4_addr_nunique': 'unique_dst_ips',
        'dst_port_nunique': 'unique_dst_ports',
        'in_bytes_sum': 'total_bytes',
        'in_packets_sum': 'total_packets',
        'is_tcp_sum': 'tcp_count',
        'is_udp_sum': 'udp_count',
        'is_icmp_sum': 'icmp_count',
        'syn_only_sum': 'count_syn_only',
        'has_rst_sum': 'count_rst',
        'well_known_port_sum': 'count_well_known_ports',
        'duration_sec_mean': 'avg_duration',
        'iat_mean': 'iat_mean',
        'iat_var': 'iat_variance',
        'is_botnet_flow_max': 'is_botnet'
    })

    print("Calculating final ratios and percentages (V2 Features)...")
    
    # Merge the port symmetry calculations
    grouped = pd.merge(grouped, symmetry_counts, on=['src4_addr', 'time_window'], how='left')
    grouped['port_symmetry'] = grouped['port_symmetry'].fillna(0)

    # Handle IAT variance NaNs
    grouped['iat_variance'] = grouped['iat_variance'].fillna(0)
    
    # Flow count denominator
    flow_counts = grouped['flow_count'].replace(0, 1) # Prevent div by zero
    
    # Standard averages
    grouped['avg_bytes_per_flow'] = grouped['total_bytes'] / flow_counts
    grouped['avg_packets_per_flow'] = grouped['total_packets'] / flow_counts
    
    # Protocol Percentages
    grouped['pct_tcp'] = (grouped['tcp_count'] / flow_counts) * 100
    grouped['pct_udp'] = (grouped['udp_count'] / flow_counts) * 100
    grouped['pct_icmp'] = (grouped['icmp_count'] / flow_counts) * 100
    
    # Port Percentages
    grouped['pct_well_known_ports'] = (grouped['count_well_known_ports'] / flow_counts) * 100
    grouped['pct_high_ports'] = 100 - grouped['pct_well_known_ports']
    
    # --- NEW V2 METRICS ---
    
    # 2. Horizontal/Vertical Scan Ratio: (unique_ips / unique_ports)
    unique_ports = grouped['unique_dst_ports'].replace(0, 1)
    grouped['ip_port_ratio'] = grouped['unique_dst_ips'] / unique_ports
    
    # 3. Payload Delivery Ratio: (bytes / packets)
    total_packets = grouped['total_packets'].replace(0, 1)
    grouped['avg_payload_per_packet'] = grouped['total_bytes'] / total_packets
    
    # 4. Failure Rate Percentages
    grouped['pct_syn_only'] = (grouped['count_syn_only'] / flow_counts) * 100
    grouped['pct_rst'] = (grouped['count_rst'] / flow_counts) * 100
    
    # 5. Periodicity Detection (Beaconing CV)
    iat_std = np.sqrt(grouped['iat_variance'])
    iat_means = grouped['iat_mean'].replace(0, 1)
    grouped['iat_cv'] = iat_std / iat_means
    
    # Mask out cv where iat_mean is legitimately 0
    grouped.loc[grouped['iat_mean'] == 0, 'iat_cv'] = 0

    features_to_keep = [
        'src4_addr', 'time_window', 
        'flow_count', 'unique_dst_ips', 'unique_dst_ports', 
        'total_bytes', 'total_packets', 'avg_bytes_per_flow', 'avg_packets_per_flow',
        'pct_tcp', 'pct_udp', 'pct_icmp',
        'pct_well_known_ports', 'pct_high_ports',
        'avg_duration', 'iat_mean', 'iat_variance',
        'port_symmetry', 'ip_port_ratio', 'avg_payload_per_packet',
        'pct_syn_only', 'pct_rst', 'iat_cv',
        'is_botnet'
    ]
    
    final_df = grouped[features_to_keep]

    print(f"Extracted {len(final_df):,} Feature V2 rows (5-minute windows).")
    
    botnet_windows = final_df['is_botnet'].sum()
    normal_windows = len(final_df) - botnet_windows
    print(f"  Botnet windows: {botnet_windows:,}")
    print(f"  Normal windows: {normal_windows:,}")
    
    if botnet_windows > 0:
        imbalance = normal_windows / botnet_windows
        print(f"  Imbalance Ratio (scale_pos_weight): {imbalance:.2f}")

    print(f"Saving to {output_path}...")
    final_df.to_csv(output_path, index=False)
    print("Done!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_features_v2.py <input.json> <output.csv>")
        sys.exit(1)
        
    in_file = sys.argv[1]
    out_file = sys.argv[2]
    
    if not os.path.exists(in_file):
        print(f"Error: input file '{in_file}' not found.")
        sys.exit(1)
        
    extract_features_v2(in_file, out_file)
