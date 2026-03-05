<!-- Copilot instructions for contributors and AI coding agents -->
# Project snapshot

This repository analyzes NetFlow records and applies lightweight detections plus YARA rule matching to surface suspicious hosts.

# Big picture (what to know first)
- Entrypoint: `main.py` — loads YARA rules, reads a NetFlow file (usually `test_netflow.json`) and calls `process_netflow_data_with_features`.
- Flow: `main.py` -> `process_netflow.py` (I/O, normalization, orchestration) -> `netflow_features.py` (feature detectors) -> `yara_rules_loader.py` (YARA compile + match).
- Data: two supported input shapes: `json` (list of dicts with keys like `src4_addr`, `dst4_addr`, `in_bytes`) and a custom `raw` text format which `convert_raw_flow_to_json()` converts to JSON. See `KEYS_CONFIG` in `process_netflow.py` for the mapping.

# Key files and patterns (quick map)
- `main.py`: simple runner. Example run: `python main.py`.
- `process_netflow.py`: handles loading, conversion, orchestration and final scoring. Important symbols: `KEYS_CONFIG`, `convert_raw_flow_to_json()`, `process_netflow_data_with_features()` and the offense weight tables.
- `netflow_features.py`: small detectors returning suspicious IP lists: `detect_frequency_of_connections()`, `detect_ip_reuse()`, `detect_p2p_traffic()`, `detect_packet_size_anomalies()`.
- `yara_rules_loader.py`: compiles multiple YARA files and calls `rule.match(data=json.dumps(flow))`. Rules live in `rules/` (e.g. `c2_behavioral_patterns.yar`).

# Project-specific conventions and gotchas
- Two data formats are supported: use `KEYS_CONFIG` keys — `json` uses `src4_addr`/`dst4_addr`, `raw` uses `src addr`/`dst addr`. Agents editing data access code must update `KEYS_CONFIG` accordingly.
- The raw-to-json converter writes to a hard-coded path in some code paths (`F:/converted_netflow.json`) — prefer updating to a relative/temp path if changing conversion behavior.
- YARA usage: rules are compiled with the `yara` module and matched against the JSON-serialized flow (`json.dumps(flow)`). When modifying rule-matching behavior, preserve the `data=` call shape to avoid changing rule semantics.
- Scoring: `process_netflow_data_with_features()` mixes feature counts and weights (see `offense_weights` and `yara_rule_weights`). Changes to detection output should consider how weights are applied and how `total_features` is computed.

# Dependencies & runtime
- Python modules: `yara` (imported as `yara`) and stdlib modules. Install `yara-python`/`yara` via pip in your environment before running.
- Run locally: `python main.py` (uses `test_netflow.json` by default).

# Examples to reference when coding
- To add a new detection, implement a function in `netflow_features.py` that returns a list of suspicious source IPs and call it from `process_netflow_data_with_features()` alongside the other detectors.
- To add a new YARA rule, drop a `.yar` file into `rules/` and add its path to `rule_files` in `main.py` (or make rule discovery dynamic).

# Tests & workflow notes
- There are no formal tests in the repo. Use the sample files `test_netflow.json` / `converted_netflow.json` to validate changes.
- For iterative development: run `python main.py`, inspect printed `Suspicious IP:` lines and returned structure from `process_netflow_data_with_features()`.

# When you are an AI agent: do this first
1. Read `main.py`, `process_netflow.py`, `netflow_features.py`, `yara_rules_loader.py` to understand data flow.
2. Preserve `KEYS_CONFIG` mappings unless you intentionally change input shapes; update all call-sites.
3. If modifying conversion, remove hard-coded `F:/` absolute paths and use repository-relative paths or temporary files.
4. When touching YARA, keep matching using `json.dumps(flow)` unless tests/consumers need a different input shape.

# Questions for the maintainer (ask before major changes)
- Should converted raw flows be written inside the repository (e.g., `converted_netflow.json`) instead of `F:/`?
- Should rule discovery be automated instead of hard-coding `rule_files` in `main.py`?

-- End of instructions
