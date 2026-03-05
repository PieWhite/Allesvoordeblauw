"""
Binetflow to Netflow JSON Converter
====================================
Converts CTU-13 binetflow CSV files into the JSON format used by our Go C2 detector.

CTU-13 binetflow columns:
    StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State,
    sTos, dTos, TotPkts, TotBytes, SrcBytes, Label

Target netflow JSON fields (from test_netflow.json):
    type, proto, tcp_flags, src_port, dst_port, in_packets, in_bytes,
    src4_addr, dst4_addr, first, last, received, export_sysid, ...

Usage:
    python convert_binetflow.py <input.binetflow> [output.json]
    python convert_binetflow.py <input_directory>   (converts all .binetflow files)

The Label column from CTU-13 is preserved as a "label" field in the JSON output,
which is useful for training ML models (it marks flows as Botnet/Normal/Background).
"""

import csv
import json
import sys
import os
import glob
from datetime import datetime, timedelta

# Protocol name → number mapping (netflow uses numeric protocol IDs)
PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "igmp": 2,
    "ipv6-icmp": 58,
    "arp": 0,        # not a real proto number, placeholder
    "rtp": 0,        # mapped at application layer
    "rtcp": 0,
    "pim": 103,
    "ipx/spx": 0,
    "udt": 0,
    "unas": 0,
}

# Binetflow State → approximate TCP flags mapping
# Binetflow uses Argus state notation (e.g., "S_FA", "PA_PA")
# We map common patterns to nfdump-style TCP flag strings
def state_to_tcp_flags(state, proto):
    """Convert Argus connection state to approximate TCP flags string."""
    if proto != 6:  # only TCP has meaningful flags
        return "........"

    state = state.upper().strip() if state else ""

    # Map common Argus state patterns
    flag_map = {
        "S_FA": ".A.S...F",    # SYN then FIN-ACK (normal close)
        "S_A": "..AS....",     # SYN then ACK (established)
        "FA_FA": ".A.....F",   # FIN-ACK both directions
        "PA_PA": "..A.P...",   # PUSH-ACK both directions
        "S_": "....S...",      # SYN only (scan or failed)
        "SR_A": "..AS.R..",    # SYN-RST then ACK
        "A_A": "..A.....",     # ACK both directions
        "S_R": "....S.R.",     # SYN then RST (rejected)
        "R_": ".....R..",      # RST only
        "SR_": "....S.R.",     # SYN-RST
    }

    for pattern, flags in flag_map.items():
        if state.startswith(pattern):
            return flags

    # Default: just ACK for anything established
    if "A" in state:
        return "..A....."
    return "........"


def parse_port(port_str):
    """Parse a port value, handling non-numeric ports (e.g., hex, names)."""
    if not port_str or port_str.strip() == "":
        return 0
    port_str = port_str.strip()
    try:
        return int(port_str)
    except ValueError:
        # Some binetflow files have hex ports like 0x0303
        if port_str.startswith("0x"):
            try:
                return int(port_str, 16)
            except ValueError:
                return 0
        return 0


def parse_timestamp(ts_str):
    """Parse binetflow timestamp to ISO format used by our netflow JSON."""
    ts_str = ts_str.strip()
    # CTU-13 timestamps: "2011/08/10 09:46:53.047277"
    # Target format:      "2024-04-22T00:00:17.896"
    for fmt in [
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
        except ValueError:
            continue

    # Fallback: return as-is with T separator
    return ts_str.replace(" ", "T")


def convert_record(row):
    """Convert a single binetflow CSV row to netflow JSON record."""
    proto_str = row.get("Proto", "").strip().lower()
    proto_num = PROTO_MAP.get(proto_str, 0)

    src_port = parse_port(row.get("Sport", "0"))
    dst_port = parse_port(row.get("Dport", "0"))

    # Parse packets and bytes, with fallbacks
    try:
        in_packets = int(row.get("TotPkts", "0").strip())
    except ValueError:
        in_packets = 0

    try:
        in_bytes = int(row.get("TotBytes", "0").strip())
    except ValueError:
        in_bytes = 0

    # Parse timestamps
    start_time = parse_timestamp(row.get("StartTime", ""))

    # Calculate end time from start + duration
    try:
        duration = float(row.get("Dur", "0").strip())
    except ValueError:
        duration = 0.0

    if duration > 0 and start_time:
        try:
            start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S.%f")
            end_dt = start_dt + timedelta(seconds=duration)
            end_time = end_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{end_dt.microsecond // 1000:03d}"
        except ValueError:
            end_time = start_time
    else:
        end_time = start_time

    state = row.get("State", "").strip()

    # Build the netflow JSON record matching our Go detector's expected format
    record = {
        "type": "FLOW",
        "proto": proto_num,
        "tcp_flags": state_to_tcp_flags(state, proto_num),
        "src_port": src_port,
        "dst_port": dst_port,
        "in_packets": in_packets,
        "in_bytes": in_bytes,
        "src4_addr": row.get("SrcAddr", "").strip(),
        "dst4_addr": row.get("DstAddr", "").strip(),
        "first": start_time,
        "last": end_time,
        "received": start_time,
        "in_src_mac": "00:00:00:00:00:00",
        "out_dst_mac": "00:00:00:00:00:00",
        "export_sysid": 1,
        # Preserve the CTU-13 label for supervised ML training
        # Values: "Botnet", "Normal", "Background", or specific C&C labels
        "label": row.get("Label", "").strip(),
    }

    return record


def convert_file(input_path, output_path=None):
    """Convert a single binetflow file to netflow JSON."""
    if output_path is None:
        base = os.path.splitext(input_path)[0]
        output_path = base + ".json"

    print(f"Converting: {input_path}")
    print(f"Output:     {output_path}")

    records = []
    skipped = 0
    botnet_count = 0
    normal_count = 0
    background_count = 0

    with open(input_path, "r", encoding="utf-8-sig", errors="replace") as f:
        # CTU-13 binetflow files are comma-separated with a header row
        reader = csv.DictReader(f)

        for i, row in enumerate(reader):
            try:
                record = convert_record(row)
                records.append(record)

                # Count labels for summary
                label = record.get("label", "").lower()
                if "botnet" in label or "bot" in label:
                    botnet_count += 1
                elif "normal" in label:
                    normal_count += 1
                elif "background" in label:
                    background_count += 1

            except Exception as e:
                skipped += 1
                if skipped <= 5:
                    print(f"  Warning: skipped row {i+1}: {e}")
                elif skipped == 6:
                    print(f"  (further warnings suppressed)")

            # Progress indicator for large files
            if (i + 1) % 100000 == 0:
                print(f"  Processed {i+1:,} rows...")

    # Write JSON output
    print(f"  Writing {len(records):,} records to JSON...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    print(f"\nDone!")
    print(f"  Total records: {len(records):,}")
    print(f"  Botnet flows:  {botnet_count:,}")
    print(f"  Normal flows:  {normal_count:,}")
    print(f"  Background:    {background_count:,}")
    print(f"  Skipped:       {skipped:,}")

    return output_path


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("Error: no input file or directory specified.")
        print("Usage: python convert_binetflow.py <input.binetflow> [output.json]")
        print("       python convert_binetflow.py <input_directory>")
        sys.exit(1)

    input_path = sys.argv[1]

    # If input is a directory, convert all binetflow files in it
    if os.path.isdir(input_path):
        files = glob.glob(os.path.join(input_path, "*.binetflow"))
        if not files:
            print(f"No .binetflow files found in {input_path}")
            sys.exit(1)

        print(f"Found {len(files)} binetflow file(s) in {input_path}\n")
        for f in sorted(files):
            convert_file(f)
            print()
    else:
        output_path = sys.argv[2] if len(sys.argv) > 2 else None
        convert_file(input_path, output_path)


if __name__ == "__main__":
    main()
