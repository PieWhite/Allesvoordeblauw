package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all configurable detection rules loaded from rules.json.
// These fields map directly to the JSON structure — no intermediate types needed.
type Config struct {
	SuspiciousPorts []int    `json:"suspicious_ports"`
	KnownC2IPs      []string `json:"known_c2_ips"`

	Thresholds struct {
		// Behavioral feature thresholds
		FrequencyOfConnections    int   `json:"frequency_of_connections"`
		IPReuseConnections        int   `json:"ip_reuse_connections"`
		P2PUniquePeers            int   `json:"p2p_unique_peers"`
		PacketSizeAnomalyMinFlows int   `json:"packet_size_anomaly_min_flows"`
		PacketSizeAnomalyAvgBytes int64 `json:"packet_size_anomaly_avg_bytes"`
		SmallAvgPacketBytes       int64 `json:"small_avg_packet_bytes"`
		MinPacketsForAvg          int64 `json:"min_packets_for_avg"`

		// Compound rule: C2_Suspicious_Ports (port + connections + time window)
		SuspiciousPortConnCount  int     `json:"suspicious_port_connection_count"`
		SuspiciousPortTimeWindow float64 `json:"suspicious_port_time_window_sec"`

		// Compound rule: C2_Behavioral_Detection (small packets + connections + time window)
		BehavioralConnCount  int     `json:"behavioral_connection_count"`
		BehavioralTimeWindow float64 `json:"behavioral_time_window_sec"`
	} `json:"thresholds"`

	Weights struct {
		FrequencyOfConnections     float64 `json:"frequency_of_connections"`
		IPReuseRepeatedConnections float64 `json:"ip_reuse_repeated_connections"`
		P2PC2Communications        float64 `json:"p2p_c2_communications"`
		PacketSizeAnomalies        float64 `json:"packet_size_anomalies"`
		C2SuspiciousPorts          float64 `json:"c2_suspicious_ports"`
		C2KnownProxies             float64 `json:"c2_known_proxies"`
		C2SmallPackets             float64 `json:"c2_small_packets"`
	} `json:"weights"`
}

// LoadConfig reads and parses a rules.json file into a Config.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", path, err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules file %s: %w", path, err)
	}

	return &config, nil
}

// Lookups holds pre-computed sets derived from config for O(1) membership checks.
type Lookups struct {
	SuspiciousPortSet map[int]bool
	KnownC2IPSet      map[string]bool
}

// NewLookups builds lookup sets from config arrays.
func NewLookups(config *Config) *Lookups {
	portSet := make(map[int]bool, len(config.SuspiciousPorts))
	for _, port := range config.SuspiciousPorts {
		portSet[port] = true
	}

	ipSet := make(map[string]bool, len(config.KnownC2IPs))
	for _, ip := range config.KnownC2IPs {
		ipSet[ip] = true
	}

	return &Lookups{
		SuspiciousPortSet: portSet,
		KnownC2IPSet:      ipSet,
	}
}
