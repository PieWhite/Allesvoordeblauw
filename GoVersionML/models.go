package main

// NetflowRecord represents a single netflow record from JSON data.
type NetflowRecord struct {
	Type        string `json:"type"`
	Proto       int    `json:"proto"`
	TCPFlags    string `json:"tcp_flags"`
	SrcPort     int    `json:"src_port"`
	DstPort     int    `json:"dst_port"`
	InPackets   int64  `json:"in_packets"`
	InBytes     int64  `json:"in_bytes"`
	Src4Addr    string `json:"src4_addr"`
	Dst4Addr    string `json:"dst4_addr"`
	First       string `json:"first"`
	Last        string `json:"last"`
	Received    string `json:"received"`
	IPNextHop   string `json:"ip_next_hop,omitempty"`
	InSrcMAC    string `json:"in_src_mac"`
	OutDstMAC   string `json:"out_dst_mac"`
	ExportSysID int    `json:"export_sysid"`
}
