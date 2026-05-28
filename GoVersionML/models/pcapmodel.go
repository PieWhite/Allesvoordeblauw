package models

type PcapRecord struct {
	Timestamp float64 `json:"timestamp"` // epoch timestamp (seconds.microseconds)
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	SrcPort   int     `json:"src_port"`
	DstPort   int     `json:"dst_port"`
	Length    int     `json:"length"`    // total size of packet in bytes
	Proto     int     `json:"proto"`     // protocol number (e.g. 6=TCP, 17=UDP, 1=ICMP)
	TCPFlags  string  `json:"tcp_flags"` // TCP flags if applicable (e.g., "S", "R", etc.)
}
