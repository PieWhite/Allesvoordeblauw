# DataConverter

Converts CTU-13 binetflow datasets into the netflow JSON format used by our Go C2 detector.

## Usage

```bash
# Convert a single file
python convert_binetflow.py capture20110810.binetflow output.json

# Convert all .binetflow files in a directory
python convert_binetflow.py ./ctu13_data/

# Default output name: same as input but .json
python convert_binetflow.py capture20110810.binetflow
```

## Getting CTU-13 Data

Download binetflow files from: https://www.stratosphereips.org/datasets-ctu13

Each scenario has a `.binetflow` file. Recommended scenarios for good botnet coverage:

| Scenario | Botnet | Topology | Flows |
|---|---|---|---|
| 1 | Neris | IRC-based C&C | ~2.8M |
| 2 | Neris | IRC-based C&C | ~1.8M |
| 3 | Rbot | IRC-based C&C | ~4.7M |
| 6 | Menti | IRC-based C&C | ~558K |
| 8 | Murlo | C&C | ~2.9M |
| 9 | Neris | IRC-based C&C | ~2.0M |
| 10 | Rbot | IRC-based C&C | ~1.3M |
| 13 | Virut | HTTP-based C&C | ~1.9M |

## Output Format

The converter produces JSON matching `test_netflow.json`:
```json
[
  {
    "type": "FLOW",
    "proto": 6,
    "tcp_flags": "..AS....",
    "src_port": 1234,
    "dst_port": 80,
    "in_packets": 5,
    "in_bytes": 320,
    "src4_addr": "147.32.84.165",
    "dst4_addr": "78.40.125.4",
    "first": "2011-08-10T09:46:53.047",
    "last": "2011-08-10T09:46:53.123",
    "label": "flow=From-Botnet"
  }
]
```

The `label` field from CTU-13 is preserved for ML training purposes.
