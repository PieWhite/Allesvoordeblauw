import csv
import json
import sys
import os
from datetime import datetime, timedelta

# Proto mapping for NetFlow numeric format
PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "igmp": 2,
    "ipv6-icmp": 58,
}

def state_to_tcp_flags(state, proto):
    """Map Argus/Binetflow states to standard TCP flags."""
    if proto != 6: return "........"
    state = state.upper().strip() if state else ""
    
    # Common mappings for CTU-13 data
    if "S_" in state and "A" not in state: return "....S..."
    if "SR_" in state: return "....S.R."
    if "R_" in state: return ".....R.."
    if "PA_PA" in state: return "..A.P..."
    if "A_" in state: return "..A....."
    if "F" in state: return ".A.....F"
    
    return "..A....." # Default to ACK

def parse_port(p):
    try:
        return int(p)
    except:
        if str(p).startswith("0x"): return int(str(p), 16)
        return 0

def convert_neris_dataset(input_file, output_file=None):
    if not output_file:
        output_file = input_file.replace(".csv", ".json") if input_file.endswith(".csv") else input_file + ".json"

    print(f"Loading {input_file} for conversion...")
    
    records = []
    counts = {"Botnet": 0, "Normal": 0, "Background": 0, "Total": 0}
    
    with open(input_file, mode='r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            # Map CTU-13 columns to GoVersionML Expected JSON format
            proto_str = row['Proto'].lower()
            proto_num = PROTO_MAP.get(proto_str, 0)
            
            start_ts = row['StartTime'].strip()
            # 2011/08/10 09:46:53.047277 -> 2011-08-10T09:46:53.047
            try:
                dt = datetime.strptime(start_ts, "%Y/%m/%d %H:%M:%S.%f")
                start_iso = dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}"
                
                dur = float(row['Dur'])
                end_dt = dt + timedelta(seconds=dur)
                end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{end_dt.microsecond // 1000:03d}"
            except Exception:
                start_iso = start_ts.replace("/", "-").replace(" ", "T")
                end_iso = start_iso

            label = row.get('Label', '').strip()
            if "botnet" in label.lower(): counts["Botnet"] += 1
            elif "normal" in label.lower(): counts["Normal"] += 1
            else: counts["Background"] += 1

            record = {
                "type": "FLOW",
                "proto": proto_num,
                "tcp_flags": state_to_tcp_flags(row['State'], proto_num),
                "src_port": parse_port(row['Sport']),
                "dst_port": parse_port(row['Dport']),
                "in_packets": int(row['TotPkts']),
                "in_bytes": int(row['TotBytes']),
                "src4_addr": row['SrcAddr'].strip(),
                "dst4_addr": row['DstAddr'].strip(),
                "first": start_iso,
                "last": end_iso,
                "received": start_iso,
                "label": label
            }
            records.append(record)
            counts["Total"] += 1

            if counts["Total"] % 100000 == 0:
                print(f"  Processed {counts['Total']:,} records...")

    print(f"Saving to {output_file}...")
    with open(output_file, 'w') as out_f:
        json.dump(records, out_f, indent=2)

    print("-" * 30)
    print(f"Conversion Complete!")
    print(f" - Total:      {counts['Total']:,}")
    print(f" - Botnet:     {counts['Botnet']:,}")
    print(f" - Normal:     {counts['Normal']:,}")
    print(f" - Background: {counts['Background']:,}")
    print("-" * 30)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python convert_neris_dataset.py <input.csv>")
        sys.exit(1)
    convert_neris_dataset(sys.argv[1])
