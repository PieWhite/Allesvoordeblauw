import yara
import json

# Function to load YARA rules from multiple files
def load_yara_rules(rule_paths):
    rules = []
    for rule_path in rule_paths:
        try:
            rules.append(yara.compile(filepath=rule_path))
        except Exception as e:
            print(f"Error loading YARA rule from {rule_path}: {e}")
    return rules

# Function to match the YARA rules on NetFlow data
def match_yara_rules(flow_data, rules):
    matches = []
    for rule in rules:
        try:
            matches.extend(rule.match(data=json.dumps(flow_data)))
        except Exception as e:
            print(f"Error matching YARA rule: {e}")
    return matches
