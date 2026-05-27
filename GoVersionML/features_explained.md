# GoVersionML — Feature Reference Guide

This document explains each of the **21 features** (f0–f20) that the XGBoost model uses to classify an IP as botnet traffic or legitimate traffic.

Features are computed per IP address over a **5-minute sliding window** of NetFlow records. When a result is flagged and an explanation is shown, the listed features are the ones that most strongly drove the model's decision.

---

## How to Read an Explanation

A result looks something like this:

```
IP: 192.168.1.55  |  Probability: 87.3%  |  IsBotnet: true
Reasons: pct_syn_only (94.1%), unique_dst_ips (312), flow_count (890), pct_tcp (100.0%)
```

The **Reasons** list shows the top features (up to 4) that contributed most to the model's decision in that 5-minute window. The value in parentheses is the **actual measured value** for that IP, not a score.

---

## Feature Reference

### f0 — `flow_count`
**What it measures:** The total number of NetFlow records (connections/flows) originating from this IP in the 5-minute window.

**How it's computed:** Incremented by 1 for every outbound flow observed.

**How to interpret it:**
- **High value (hundreds–thousands):** The IP is initiating an unusually large number of connections. Combined with other features, this is a strong indicator of automated scanning or C2 beaconing.
- **Low value (1–10):** Normal, human-like traffic. On its own this is benign, but it can still combine with other suspicious features.

---

### f1 — `unique_dst_ips`
**What it measures:** The number of distinct destination IP addresses contacted by this IP in the window.

**How it's computed:** The size of a de-duplicated set of all `Dst4Addr` values seen in outbound flows.

**How to interpret it:**
- **High value:** The IP is reaching out to many different hosts — classic behaviour for horizontal network scanners and botnet spreaders.
- **Low value:** The IP is communicating with a narrow set of peers, typical of legitimate clients or focused (vertical) port scanners.

---

### f2 — `unique_dst_ports`
**What it measures:** The number of distinct destination ports targeted in the window.

**How it's computed:** The size of a de-duplicated set of all `DstPort` values seen in outbound flows.

**How to interpret it:**
- **High value:** The IP is sweeping across many ports, the defining characteristic of a port scan.
- **Low value:** Traffic is focused on one or a few ports, consistent with a specific service or protocol (e.g. only port 443).

---

### f3 — `total_bytes`
**What it measures:** The cumulative byte volume of all outbound flows in the window.

**How it's computed:** Sum of `InBytes` across all outbound flows. Displayed as B / KB / MB in explanations.

**How to interpret it:**
- **High value:** Large data volumes can indicate data exfiltration or a high-bandwidth attack.
- **Low value:** Typical for probe-and-scan patterns where only tiny packets are exchanged (e.g. SYN probes).

---

### f4 — `total_packets`
**What it measures:** The cumulative packet count of all outbound flows in the window.

**How it's computed:** Sum of `InPackets` across all outbound flows.

**How to interpret it:**
- **High value alongside low total_bytes:** Many tiny packets; pattern of SYN flood or ICMP sweeping.
- **High value alongside high total_bytes:** High-throughput communication; possible exfiltration or DDoS amplification.

---

### f5 — `avg_bytes_per_flow`
**What it measures:** The average byte count per individual flow.

**How it's computed:** `total_bytes / flow_count`

**How to interpret it:**
- **Very low (< 100 bytes):** Flows contain almost no payload — indicative of scanner probes (SYN-only, ICMP echo) or minimal C2 heartbeat messages.
- **Moderate (100 B – 10 KB):** Typical for interactive sessions or API calls.
- **Very high (> 100 KB):** Large file transfers; check `pct_syn_only` and `unique_dst_ips` to determine if this is legitimate.

---

### f6 — `avg_packets_per_flow`
**What it measures:** The average number of packets per flow.

**How it's computed:** `total_packets / flow_count`

**How to interpret it:**
- **Value of 1:** Nearly every flow consists of a single packet. This is the hallmark of SYN scanning or UDP probing — no response, no handshake.
- **Value of 2–5:** Short, transactional exchanges.
- **Higher values:** Multi-packet sessions consistent with established connections.

---

### f7 — `pct_tcp`
**What it measures:** The percentage of flows using TCP (protocol 6).

**How it's computed:** `(TCP flow count / total flow count) × 100`

**How to interpret it:**
- **~100%:** Almost exclusively TCP. When combined with high `pct_syn_only`, this is a strong signal of TCP SYN scanning.
- **Mixed with UDP/ICMP:** Could be a multi-protocol scanner or a device that genuinely uses multiple protocols.

---

### f8 — `pct_udp`
**What it measures:** The percentage of flows using UDP (protocol 17).

**How it's computed:** `(UDP flow count / total flow count) × 100`

**How to interpret it:**
- **High value with many `unique_dst_ports`:** UDP port scanning (e.g. probing for DNS, NTP, or memcached amplification targets).
- **High value with few `unique_dst_ports`:** Normal UDP service traffic (e.g. DNS resolver, VoIP).

---

### f9 — `pct_icmp`
**What it measures:** The percentage of flows using ICMP (protocol 1).

**How it's computed:** `(ICMP flow count / total flow count) × 100`

**How to interpret it:**
- **High value with high `unique_dst_ips`:** ICMP sweep / ping scan to discover live hosts across a subnet.
- **Low to moderate:** Background noise or routine network diagnostics.

---

### f10 — `pct_well_known_ports`
**What it measures:** The percentage of flows targeting ports below 1024 (the "well-known" port range: HTTP 80, HTTPS 443, SSH 22, etc.).

**How it's computed:** `(flows to port < 1024 / total flow count) × 100`

**How to interpret it:**
- **High value:** The IP is predominantly targeting standard services — could be a legitimate web client or a focused attacker hitting common ports (22, 23, 80, 445).
- **Low value:** Traffic is aimed at high/ephemeral ports, which may indicate peer-to-peer activity, C2 on non-standard ports, or high-port scanning.

---

### f11 — `pct_high_ports`
**What it measures:** The percentage of flows targeting ports ≥ 1024.

**How it's computed:** `100 − pct_well_known_ports`

**How to interpret it:**
- This is the inverse of `pct_well_known_ports`. A high value here combined with high `unique_dst_ports` strongly suggests random high-port scanning or C2 traffic avoiding standard port detection.

---

### f12 — `avg_duration`
**What it measures:** The average duration (in seconds) of each flow.

**How it's computed:** `SumDurationSec / flow_count`, where each flow's duration = `Last − First` timestamp.

**How to interpret it:**
- **Near zero (< 0.1 s):** Flows are essentially instantaneous — consistent with scan probes that receive no reply or are immediately reset.
- **Short (< 5 s):** Rapid transactional connections.
- **Long (> 60 s):** Persistent connections; may indicate C2 keep-alives or file transfers.

---

### f13 — `iat_mean`
**What it measures:** The mean Inter-Arrival Time (IAT) — the average time gap between consecutive flows sent to the same destination IP+port.

**How it's computed:** For each `(destination IP, destination port)` pair, flow start times are sorted and consecutive differences are taken. All differences across all pairs (plus a leading `0` per pair to match training data) are averaged.

**How to interpret it:**
- **Very low (near 0 s):** Flows are being fired in rapid bursts with no pause — scanner or flooder behaviour.
- **Highly regular (e.g. exactly 30 s, 60 s):** Periodic beaconing — a bot checking in with its C2 on a fixed schedule.
- **Irregular / high variance:** More consistent with human-driven or naturally varied traffic.

---

### f14 — `iat_variance`
**What it measures:** The statistical variance of the Inter-Arrival Times.

**How it's computed:** Sample variance (ddof=1, matching pandas default) of all IAT differences computed for `iat_mean`.

**How to interpret it:**
- **Very low variance:** Flows arrive at an almost perfectly regular interval — the hallmark of automated, clock-driven beaconing.
- **High variance:** Irregular timing, more consistent with human behaviour or bursty application traffic.
- Best interpreted together with `iat_mean` and `iat_cv`.

---

### f15 — `port_symmetry`
**What it measures:** The number of destination ports that appear in **both** outbound flows **and** inbound flows for this IP.

**How it's computed:** Count of ports present in both the outbound destination port set and the inbound destination port set.

**How to interpret it:**
- **High value:** Bidirectional traffic on many ports, consistent with established two-way communication (normal client–server exchanges).
- **Low or zero:** Outbound traffic on ports where no inbound traffic is seen — typical of scanning (probes sent, no replies received or tracked).

---

### f16 — `ip_port_ratio`
**What it measures:** The ratio of unique destination IPs to unique destination ports.

**How it's computed:** `unique_dst_ips / unique_dst_ports` (denominator floored at 1 to avoid division by zero).

**How to interpret it:**
- **High value (>> 1):** Many different IPs are reached on a small number of ports — vertical spread across hosts on the same port (e.g. scanning all hosts for port 22).
- **Low value (~1 or < 1):** Many different ports are targeted per IP — horizontal port scan against the same host(s), or a diverse mix of services.
- **Value of ~1:** Roughly one IP per port — balanced mixed scanning or diverse normal traffic.

---

### f17 — `avg_payload_per_packet`
**What it measures:** The average number of bytes per packet.

**How it's computed:** `total_bytes / total_packets` (denominator floored at 1).

**How to interpret it:**
- **Very low (< 60 bytes):** Packets carry almost no payload beyond headers — typical of SYN probes or ICMP echo requests.
- **Moderate (200–1400 bytes):** Normal application data exchanges.
- **At or near 1500 bytes:** Flows are hitting the standard Ethernet MTU — likely large bulk transfers.

---

### f18 — `pct_syn_only`
**What it measures:** The percentage of TCP flows where the SYN flag is set but no ACK, FIN, or RST flag is set.

**How it's computed:** A flow is counted as "SYN-only" if `TCPFlags` contains `S` but does not contain `A`, `F`, or `R`. The percentage is `(SYN-only count / flow count) × 100`.

**How to interpret it:**
- **High value (> 50%):** The IP is sending connection initiation packets without completing handshakes — the defining signature of a **TCP SYN scanner**. This is one of the most discriminative features in the model.
- **Low value:** Connections are either completing normally (ACK present) or being actively refused (RST present).

---

### f19 — `pct_rst`
**What it measures:** The percentage of flows that contain a TCP RST (Reset) flag.

**How it's computed:** `(RST flow count / flow count) × 100`

**How to interpret it:**
- **High value:** Many connections are being abruptly terminated or refused. This can happen when a scanner hits closed ports (the target responds with RST), or when the scanning host itself sends RSTs to tear down half-open connections quickly.
- **Low value:** Connections are completing or timing out normally.
- **Combined with high `pct_syn_only`:** Strong confirmation of SYN scan activity.

---

### f20 — `iat_cv`
**What it measures:** The **Coefficient of Variation** of the Inter-Arrival Times — a normalised measure of timing regularity that is not affected by the absolute scale of the intervals.

**How it's computed:** `sqrt(iat_variance) / iat_mean`. Returns 0 if `iat_mean` is 0.

**How to interpret it:**
- **Near zero:** The intervals between flows are almost perfectly consistent — clock-like beaconing. This is the strongest timing-based indicator of automated C2 communication.
- **> 1:** Highly erratic timing — intervals vary more than their own average, typical of bursty or human-driven traffic.
- **Between 0 and 1:** Some regularity, but with noise. Could be application retries, keep-alives with jitter, or semi-automated tools.
- Prefer `iat_cv` over raw `iat_variance` when comparing IPs with different traffic volumes, since it is scale-independent.

---

## Quick Reference Table

| Index | Feature Name             | Unit / Type        | High value suggests       | Low value suggests            |
|-------|--------------------------|--------------------|---------------------------|-------------------------------|
| f0    | `flow_count`             | count              | High-volume scanning / C2 | Low activity                  |
| f1    | `unique_dst_ips`         | count              | Horizontal spread / scan  | Focused target set            |
| f2    | `unique_dst_ports`       | count              | Port scanning             | Specific service              |
| f3    | `total_bytes`            | bytes              | Exfiltration / high-BW    | Probe / scan traffic          |
| f4    | `total_packets`          | count              | Volume attack / scan      | Low activity                  |
| f5    | `avg_bytes_per_flow`     | bytes              | Data transfer             | Probe / SYN-only              |
| f6    | `avg_packets_per_flow`   | count              | Established sessions      | Single-packet probes          |
| f7    | `pct_tcp`                | %                  | TCP scanner (+ syn_only)  | Mixed protocols               |
| f8    | `pct_udp`                | %                  | UDP scan / amplification  | TCP-primary traffic           |
| f9    | `pct_icmp`               | %                  | Host discovery sweep      | Normal traffic                |
| f10   | `pct_well_known_ports`   | %                  | Standard service targeting| High-port / C2 / P2P         |
| f11   | `pct_high_ports`         | %                  | High-port scan / C2       | Standard service targeting    |
| f12   | `avg_duration`           | seconds            | Persistent connections    | Probe / scan (no handshake)   |
| f13   | `iat_mean`               | seconds            | Slow scan / keep-alive    | Burst / rapid scan            |
| f14   | `iat_variance`           | seconds²           | Irregular timing          | Regular / beaconing           |
| f15   | `port_symmetry`          | count              | Bidirectional comms       | One-way probes                |
| f16   | `ip_port_ratio`          | ratio              | Same-port wide spread     | Per-IP port sweep             |
| f17   | `avg_payload_per_packet` | bytes              | Normal data exchange      | Header-only probes            |
| f18   | `pct_syn_only`           | %                  | **SYN scan** (key signal) | Normal handshakes             |
| f19   | `pct_rst`                | %                  | Scan + closed ports       | Normal / graceful teardown    |
| f20   | `iat_cv`                 | dimensionless      | Irregular / human timing  | **Clock-like beaconing** (C2) |

---

## Common Detection Patterns

| Pattern | Key elevated features |
|---------|-----------------------|
| **TCP SYN scanner** | `pct_syn_only`, `pct_tcp`, `flow_count`, `unique_dst_ips`, `avg_packets_per_flow ≈ 1` |
| **Port sweep** | `unique_dst_ports`, `flow_count`, `avg_duration ≈ 0` |
| **C2 beaconing** | `iat_cv ≈ 0`, `iat_variance ≈ 0`, `avg_duration` high |
| **Host discovery** | `pct_icmp`, `unique_dst_ips`, `avg_bytes_per_flow` low |
| **Data exfiltration** | `total_bytes`, `avg_bytes_per_flow`, `avg_duration` high |
| **UDP amplification probe** | `pct_udp`, `unique_dst_ips`, `pct_well_known_ports` |

---

*Source files: [`ipstats.go`](engine/ipstats.go) · [`explainer.go`](engine/explainer.go) · [`aggregator.go`](engine/aggregator.go) · [`detector.go`](engine/detector.go)*
