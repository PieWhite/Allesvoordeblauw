import json
import sys
import os

def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_test_json.py <raw_master_input.json> <output_test.json>")
        sys.exit(1)
        
    in_file = sys.argv[1]
    out_file = sys.argv[2]
    ip_file = 'test_set_ips.txt'
    
    if not os.path.exists(ip_file):
        print(f"Error: Could not find {ip_file}. Run train_model.py first to generate the Test Set split!")
        sys.exit(1)
        
    # Load the specific IPs that were chosen for the ML Test set
    with open(ip_file, 'r') as f:
        test_ips = {line.strip() for line in f if line.strip()}
        
    print(f"Loaded {len(test_ips)} IPs that make up the Test Set.")
    print(f"Scanning raw flows in {in_file}...")
    
    try:
        # Since extract_features_v2.py uses pd.read_json, we know it fits in RAM
        with open(in_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        print(f"Successfully loaded {len(data):,} total raw flows.")
        
        # Filter: Only keep flows where the Source IP (the entity being evaluated) is in the Test set
        # We also keep it if it's the destination, to ensure bidirectional context (port symmetry) works!
        filtered = [record for record in data if record.get('src4_addr') in test_ips or record.get('dst4_addr') in test_ips]
        
        print(f"Extracted {len(filtered):,} flows that belong exclusively to the Test Set IPs.")
        
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(filtered, f)
            
        print(f"\nSaved Test split to {out_file}!")
        print("You can now feed this file into goversionML.exe to verify the Engine's inference results vs Python!")
        
    except memoryError:
        print("Memory Error: JSON array is too large. Consider using NDJSON streaming.")

if __name__ == "__main__":
    main()
