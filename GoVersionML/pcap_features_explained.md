# GoVersionML — PCAP Feature Reference Guide

This document explains each of the **39 features** (f0–f38) that the XGBoost model uses to classify an IP as botnet traffic or legitimate traffic within the **PCAP Pipeline**.

PCAP features are calculated directly from raw packet headers and align with the **CICIoT2023** schema, optimized for packet-level micro-behaviors observed over a **5-minute sliding window**.

---

## How to Read an Explanation

When a result is flagged as a botnet, the detailed explanation will show the top features (up to 4) that drove the classification decision:

```
IP: 185.100.233.162 | ML Probability: 69.4% | BOTNET
Reasons: ack_count (34506), Min (60.0B), Number (34703), fin_count (28)
```

The values shown in the parentheses represent the **actual measured statistics** for that host inside the 5-minute window.

---

## Part 1: Header Flags & TCP Counts

These features track how the host manipulates low-level connection states.

### f3 — `fin_flag_number` & f12 — `fin_count`
* **What they measure**: `fin_flag_number` is the proportion (0% to 100%) of packets containing the TCP `FIN` flag. `fin_count` is the raw count of `FIN` packets.
* **Why it matters**: Clean connection closures require `FIN` packets. During botnet flooding attacks, this ratio drops to near-zero as attackers dump one-way stateless packets without properly closing sessions.

### f4 — `syn_flag_number` & f10 — `syn_count`
* **What they measure**: `syn_flag_number` is the proportion of packets containing the `SYN` (Synchronize) flag. `syn_count` is the raw count.
* **Why it matters**: An unusually high SYN proportion (e.g. >50%) is the classic signature of a **TCP SYN Flood** or aggressive horizontal port scanning.

### f5 — `rst_flag_number` & f13 — `rst_count`
* **What they measure**: `rst_flag_number` is the proportion of packets containing the `RST` (Reset) flag. `rst_count` is the raw count.
* **Why it matters**: A high volume of reset packets indicates either the scanning of closed ports (where targets reply with RST) or an attacking node sending resets to forcibly tear down half-open TCP states.

### f6 — `psh_flag_number`
* **What it measures**: The proportion of TCP packets with the `PSH` (Push) flag enabled.
* **Why it matters**: Normal interactive traffic (like SSH keystrokes or HTTP transfers) has a high proportion of PSH flags. Low PSH ratios with huge packet counts indicate stateless automated flooding.

### f7 — `ack_flag_number` & f11 — `ack_count`
* **What they measure**: `ack_flag_number` is the proportion of TCP packets containing the `ACK` (Acknowledgment) flag. `ack_count` is the raw count.
* **Why it matters**: If `ack_flag_number` is near 100% and packet volume is massive, this is the signature of a **TCP ACK Flood** (using stateless, bare ACK packets to overwhelm target state-tables).

### f8 — `ece_flag_number` & f9 — `cwr_flag_number`
* **What they measure**: The proportions of TCP packets with Congestion Notification flags (`ECE` and `CWR`) set.
* **Why it matters**: Rare in raw botnet floods since attack scripts rarely simulate congestion control dynamics.

---

## Part 2: Volumetric & Packet-Size Metrics

These features detect rigid mathematical structures in packet sizes and timing.

### f0 — `Header_Length`
* **What it measures**: The average size of the transport layer header (TCP/UDP/ICMP header length) across all packets.
* **Why it matters**: Standard TCP headers are 20 bytes (or more with options), whereas UDP headers are 8 bytes. An average value of exactly 20.0B indicates bare TCP packets.

### f1 — `Time_To_Live`
* **What it measures**: The average Time-to-Live (TTL) field of the packets.
* **Why it matters**: Normal traffic contains mixed TTLs depending on client OS and distance. Automated attack scripts often hardcode TTL values (e.g. exactly 64) which shows up as a perfectly rigid average.

### f2 — `Rate`
* **What it measures**: Transmission rate in packets per second (pps).
* **Why it matters**: Extremely high pps rates are typical of high-velocity Denial of Service floods.

### f29 — `Tot sum`
* **What it measures**: The cumulative size of all packet payloads and headers in bytes.
* **Why it matters**: Reflects the overall bandwidth volume of the communications.

### f30 — `Min` & f31 — `Max`
* **What they measure**: The minimum and maximum packet size observed in the window.
* **Why it matters**: Flooding attacks tend to send static-sized packets (e.g. `Min` = `Max` = 60 bytes or 64 bytes) to maximize packet-generation speed. Normal traffic has highly dynamic sizes (ranging from 60B up to 1500B MTU).

### f32 — `AVG` & f34 — `Tot size`
* **What they measure**: The average packet size in bytes.
* **Why it matters**: Low values (e.g. < 70B) indicate tiny, payload-less packets designed for floods or scanning.

### f33 — `Std` & f37 — `Variance`
* **What they measure**: The standard deviation and statistical variance of packet lengths.
* **Why it matters**: Standard traffic is highly variable (high standard deviation). Botnet floods have nearly zero variance because every packet has an identical byte structure.

### f35 — `IAT`
* **What it measures**: Mean Inter-Arrival Time (seconds) — the average time gap between consecutive packets.
* **Why it matters**: Near-zero values (e.g., < 0.005s) mean packets are arriving in a rapid stream, consistent with denial-of-service floods.

### f36 — `Number`
* **What it measures**: The total packet count processed for this IP in the window.
* **Why it matters**: Reflects the overall density of the packets.

### f38 — `Protocol Type`
* **What it measures**: The predominant IP protocol layer. Automatically translates to a string like `TCP`, `UDP`, `ICMP`, or `IGMP`.
* **Why it matters**: Quickly pinpoints the transport layer protocol used by the botnet traffic.

---

## Part 3: Protocol & Port Ratios (f14–f28)

These features measure the proportion of packets matching specific protocols or ports to identify the attack surface:

| Feature Name | Description | Elevated meaning |
|---|---|---|
| `TCP` (f22) | Proportion of TCP packets | High TCP Floods (SYN, ACK) |
| `UDP` (f23) | Proportion of UDP packets | UDP Floods or amplification attacks |
| `ICMP` (f26) | Proportion of ICMP packets | ICMP Flood or ping sweep scanning |
| `IGMP` (f14) | Proportion of IGMP packets | Multicast-related flooding |
| `HTTPS` (f15) | Proportion targeting HTTPS (443) | Target is secure web services |
| `HTTP` (f16) | Proportion targeting HTTP (80) | HTTP Flooding / application DDoS |
| `Telnet` (f17)| Proportion targeting Telnet (23) | Telnet scanning / brute forcing (Mirai spreads here) |
| `DNS` (f18) | Proportion targeting DNS (53) | DNS amplification or query flood |
| `SMTP` (f19) | Proportion targeting SMTP (25) | Spamming or SMTP enumeration |
| `SSH` (f20) | Proportion targeting SSH (22) | SSH brute-forcing or scanning |
| `IRC` (f21) | Proportion targeting IRC (194/6667) | Command-and-control connection |
| `DHCP` (f24) | Proportion of DHCP packets | DHCP starvation attempts |
| `ARP` (f25) | Proportion of ARP packets | ARP poisoning / spoofing |
| `IPv` (f27) | Proportion of standard IP packets | Standard internet routing check |
| `LLC` (f28) | Proportion of Logical Link Control packets | Non-routing network discovery |

---

## Common Botnet Fingerprints

When reading PCAP explanations, look for these common pattern signatures:

| Attack Vector | Defining Reasons / Metrics |
|---|---|
| **TCP ACK Flood** | `ack_count` is extremely high, `Min` is exactly 60.0B, `fin_count` is near-zero, and `Protocol Type` is `TCP`. |
| **TCP SYN Flood** | `syn_count` is extremely high, `syn_flag_number` is near 100%, and `Header_Length` is around 20B. |
| **UDP Flood / Amplification**| `UDP` is near 100%, `Rate` is very high, `Tot sum` is massive, and `Protocol Type` is `UDP`. |
| **Telnet Botnet Propagation** | `Telnet` has a high ratio, `Number` is elevated, and `Min` is low (typical Mirai scanner). |
| **Mirai ICMP Sweep** | `ICMP` is elevated, `Rate` is high, and `Min` is around 74.0B. |

*Source components: [`explainer.go`](engine/explainer.go) · [`pcap_detector.go`](engine/pcap_detector.go)*
