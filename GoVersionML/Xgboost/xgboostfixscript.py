import os
import re

def fix_xgboost_json_ultimate(input_json, output_json):
    print(f"Loading model from {input_json}...")
    
    if not os.path.exists(input_json):
        print(f"Error: Could not find {input_json}.")
        return

    with open(input_json, 'r') as file:
        model_text = file.read()

    # The exact 36 V5 Features your Go Aggregator outputs
    core_features = [
        "flows_per_second", "bytes_per_second", "packets_per_second",
        "unique_dst_ips", "unique_dst_ports", "unique_src_ports",
        "avg_bytes_per_flow", "avg_packets_per_flow",
        "bytes_std", "packets_std", "bpp_std", "bpp_iqr",
        "dst_ip_entropy", "src_port_entropy", "top_dst_port_share_pct",
        "dominant_bpp_count_p75", "dominant_bpp_count_p90",
        "pct_tcp", "pct_udp", "pct_icmp",
        "pct_well_known_ports", "pct_high_ports",
        "pct_ephemeral_src_ports", "pct_well_known_src_ports",
        "pct_client_initiated", "pct_server_initiated",
        "avg_duration", "iat_mean", "iat_variance", "iat_cv",
        "port_symmetry", "ip_port_ratio", "avg_payload_per_packet",
        "pct_syn_only", "pct_rst", "burst_max_flows_per_min"
    ]

    print("Mapping the 36 Core V5 features...")
    replace_count = 0
    for index, feature_name in enumerate(core_features):
        old_string = f'"{feature_name}"'
        new_string = f'"f{index}"'
        occurrences = model_text.count(old_string)
        replace_count += occurrences
        model_text = model_text.replace(old_string, new_string)

    # Now, find ANY remaining string that isn't an 'f' index
    # XGBoost JSON splits look exactly like this: "split": "feature_name"
    print("\nScanning for ghost features...")
    
    # Regex to find all "split": "something"
    matches = re.findall(r'"split":\s*"([^"]+)"', model_text)
    
    # Filter out the ones that are already fixed (f0, f1, f2...)
    ghost_features = set([m for m in matches if not re.match(r'^f\d+$', m)])
    
    if ghost_features:
        print(f"Found {len(ghost_features)} ghost feature(s) hiding in the JSON:")
        
        # Start mapping ghost features starting at index 36
        ghost_start_index = len(core_features) 
        
        for ghost in ghost_features:
            old_string = f'"{ghost}"'
            new_string = f'"f{ghost_start_index}"'
            occurrences = model_text.count(old_string)
            replace_count += occurrences
            
            print(f"  Mapped ghost '{ghost}' -> 'f{ghost_start_index}' ({occurrences} splits)")
            model_text = model_text.replace(old_string, new_string)
            ghost_start_index += 1
    else:
        print("No additional ghost features found!")

    print(f"\nSaving repaired model to {output_json}...")
    with open(output_json, 'w') as file:
        file.write(model_text)
        
    print(f"Done! Safely modified {replace_count} decision tree nodes.")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, "xgboostv5_2.json")
    output_path = os.path.join(script_dir, "botnet_xgboost_fixed_v5_2.json")
    fix_xgboost_json_ultimate(input_path, output_path)