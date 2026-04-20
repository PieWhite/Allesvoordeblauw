package models

type NetflowRecord struct {
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

// MLResult holds the final model prediction for a single IP.

type MLResult struct {
	IP          string
	Probability float64
	IsBotnet    bool
}
