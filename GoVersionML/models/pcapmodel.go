package models

type ConnID struct {
	OrigH string `json:"orig_h"`
	OrigP int    `json:"orig_p"`
	RespH string `json:"resp_h"`
	RespP int    `json:"resp_p"`
}

type PcapRecord struct {
	TS            float64 `json:"ts"`
	UID           string  `json:"uid"`
	ID            ConnID  `json:"id"`
	Proto         string  `json:"proto"`
	Service       string  `json:"service"`
	Duration      float64 `json:"duration"`
	OrigBytes     int64   `json:"orig_bytes"`
	RespBytes     int64   `json:"resp_bytes"`
	ConnState     string  `json:"conn_state"`
	LocalOrig     bool    `json:"local_orig"`
	LocalResp     bool    `json:"local_resp"`
	MissedBytes   int64   `json:"missed_bytes"`
	History       string  `json:"history"`
	OrigPkts      int64   `json:"orig_pkts"`
	OrigIPBytes   int64   `json:"orig_ip_bytes"`
	RespPkts      int64   `json:"resp_pkts"`
	RespIPBytes   int64   `json:"resp_ip_bytes"`
	TunnelParents string  `json:"tunnel_parents"`
	Label         string  `json:"label"`
	DetailedLabel string  `json:"detailed-label"`
}
