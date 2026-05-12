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

type MLResult struct {
	IP          string
	Probability float64
	IsBotnet    bool
}

type ScanResult struct {
	Records *[]NetflowRecord
	Err     error
}
