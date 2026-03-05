from yara_rules_loader import load_yara_rules
from process_netflow import load_netflow_data, process_netflow_data_with_features

import os
import time

if __name__ == "__main__":
    start_time = time.time()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    rule_files = [
        os.path.join(script_dir, "rules/c2_suspicious_ports.yar"), 
        os.path.join(script_dir, "rules/c2_behavioral_patterns.yar"), 
        os.path.join(script_dir, "rules/c2_known_proxies.yar")
    ]
    
    yara_rules = load_yara_rules(rule_files)
    
    netflow_path = os.path.join(script_dir, 'test_netflow.json')
    netflow_data, data_format = load_netflow_data(netflow_path)
    
    suspicious_flows = process_netflow_data_with_features(netflow_data, data_format, yara_rules)
    
    end_time = time.time()
    print(f"Execution time: {end_time - start_time:.4f} seconds")
