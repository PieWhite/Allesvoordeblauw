package models

type NDJsonRecord struct {
	First     string `json:"first"`
	Last      string `json:"last"`
	InPackets int64  `json:"in_packets"`
	InBytes   int64  `json:"in_bytes"`
	Proto     int    `json:"proto"`
	TCPFlags  string `json:"tcp_flags"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Src4Addr  string `json:"src4_addr"`
	Dst4Addr  string `json:"dst4_addr"`
}

// Required fields for V5 training/inference feature extraction:

// first
// last
// in_packets
// in_bytes
// proto
// tcp_flags
// src_port
// dst_port
// src4_addr
// dst4_addr
// I also recommend adding optional role hints later if available:

// is_internal_src
// is_internal_dst
// These are optional but improve initiator/C2-role features.
