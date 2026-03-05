import json
import csv
import re
from datetime import datetime
from yara_rules_loader import load_yara_rules, match_yara_rules
from netflow_features import detect_frequency_of_connections, detect_ip_reuse, detect_p2p_traffic, detect_packet_size_anomalies
from collections import defaultdict

KEYS_CONFIG = {
    "json": {
        "src_ip": "src4_addr",
        "dst_ip": "dst4_addr",
        "src_port": "src_port",
        "dst_port": "dst_port",
        "bytes": "in_bytes",
        "proto": "proto"
    },
    "raw": {
        "src_ip": "src addr",
        "dst_ip": "dst addr",
        "src_port": "src port",
        "dst_port": "dst port",
        "bytes": "in_bytes",
        "proto": "proto"
    }
}

def load_netflow_data(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file), "json"
    except json.JSONDecodeError:
        convert_raw_flow_to_json(file_path, 'F:/converted_netflow.json')
        with open('F:/converted_netflow.json', 'r') as file:
            return json.load(file), "json"
    except Exception as e:
        print(f"Error: Unable to load the file. {e}")
        raise

def convert_raw_flow_to_json(input_file, output_file):
    data = []
    with open(input_file, 'r') as file:
        flow = {}
        for line in file:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith("Flow Record:"):
                if flow:
                    data.append(flow)
                flow = {"type": "FLOW", "sampled": 1, "label": "<none>"}
                continue
            
            # Extract key-value pairs
            match = re.match(r"(.+?)\s+=\s+(.+)", line)
            if match:
                key, value = match.groups()
                key = key.strip().lower().replace(" ", "_")
                if key in ["first", "last", "received_at"]:
                    timestamp_match = re.search(r"\[(.+?)\]", value)
                    if timestamp_match:
                        value = timestamp_match.group(1).replace(" ", "T")
                        key = key.replace("_at", "") 
                elif key == "src_addr":
                    key = "src4_addr"
                elif key == "dst_addr":
                    key = "dst4_addr"
                elif key == "proto":
                    value = int(value.split()[0])
                elif key == "tcp_flags":
                    value = value.split()[-1]
                elif key in ["in_packets", "in_bytes", "src_port", "dst_port", "src_tos", "export_sysid"]:
                    value = int(value)
                flow[key] = value
        
        if flow:
            data.append(flow)
    
    with open(output_file, 'w') as json_file:
            json.dump(data, json_file, indent=4)
    print(f"Converted raw flow records to JSON: {output_file}")

def process_netflow_data_with_features(netflow_data, data_format, yara_rules):
    suspicious_flows = defaultdict(lambda: defaultdict(int))


    offense_weights = {
        'Frequency of Connections': 1,
        'IP Reuse & Repeated Connections': 1, 
        'P2P C2 Communications': 75,
        'Packet Size Anomalies': 75,
    }
    
    yara_rule_weights = {
        'C2_Behavioral_Detection': 1,
        'C2_Suspicious_Ports': 1, 
        'C2_Known_Proxies': 1
    }
    
    total_possible_weight = sum(offense_weights.values()) + sum(yara_rule_weights.values()) 

    if not netflow_data:
        print("Error: NetFlow data is empty.")
        return suspicious_flows
    
    keys = KEYS_CONFIG[data_format]

    if isinstance(netflow_data, list):
        for flow in netflow_data:
            if keys["src_ip"] not in flow or keys["dst_ip"] not in flow or keys["bytes"] not in flow:
                print(f"Warning: Missing expected keys in flow data: {flow}")
                continue

    suspicious_ips_by_freq = set(detect_frequency_of_connections(netflow_data, keys))
    for ip in suspicious_ips_by_freq:
        suspicious_flows[ip]['Frequency of Connections'] = 1

    suspicious_ips_by_reuse = set(detect_ip_reuse(netflow_data, keys))
    for ip in suspicious_ips_by_reuse:
        suspicious_flows[ip]['IP Reuse & Repeated Connections'] = 1

    suspicious_ips_by_p2p = set(detect_p2p_traffic(netflow_data, keys))
    for ip in suspicious_ips_by_p2p:
        suspicious_flows[ip]['P2P C2 Communications'] = 1

    suspicious_ips_by_size = set(detect_packet_size_anomalies(netflow_data, keys))
    for ip in suspicious_ips_by_size:
        suspicious_flows[ip]['Packet Size Anomalies'] = 1    

    for flow in netflow_data:
        if keys["src_ip"] in flow and keys["dst_ip"] in flow and keys["src_port"] in flow and keys["dst_port"] in flow:
            matches = match_yara_rules(flow, yara_rules)
            if matches:
                for match in matches:
                    rule_name = match.rule
                    # Treat yara rules as boolean flags as well
                    suspicious_flows[flow.get(keys["src_ip"], 'Unknown IP')][rule_name] = 1
                    
                    if rule_name in yara_rule_weights:
                        offense_weights[rule_name] = yara_rule_weights[rule_name]

    formatted_suspicious_flows = {}
    for ip, features in suspicious_flows.items():
        formatted_suspicious_flows[ip] = {feature: "(Triggered)" for feature in features.keys()}

    formatted_output = {}
    for ip, features in formatted_suspicious_flows.items():        
        weighted_risk_score = 0
        for feature in features.keys():
            if feature in offense_weights:
                weight = offense_weights[feature]
                weighted_risk_score += weight  # Only add the weight once since count is always 1
        
        risk_factor = (weighted_risk_score / total_possible_weight) * 100
        risk_factor = round(risk_factor, 2) 
        
        # Cap risk factor at 100% just in case
        risk_factor = min(risk_factor, 100.0)

        reasons_str = ", ".join([f"{reason}" for reason in features.keys()])
        
        if risk_factor != 0:
            formatted_output[ip] = {
                "reasons": reasons_str,
                "risk_factor": f"{risk_factor}%" 
            }

    sorted_output = sorted(formatted_output.items(), key=lambda x: float(x[1]['risk_factor'].replace('%', '')), reverse=True)

    for ip, details in sorted_output:
        print(f"Suspicious IP: {ip} - Reasons: {details['reasons']} - Risk Factor: {details['risk_factor']}")

    return formatted_output
    