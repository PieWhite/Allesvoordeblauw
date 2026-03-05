package main

// Feature name constants used by rules and the scorer.
// Centralised here to eliminate magic strings and ensure compile-time safety.
const (
	FeatureFrequencyOfConnections = "Frequency of Connections"
	FeatureIPReuse                = "IP Reuse & Repeated Connections"
	FeatureP2P                    = "P2P C2 Communications"
	FeaturePacketSize             = "Packet Size Anomalies"
	FeatureSuspiciousPorts        = "C2_Suspicious_Ports"
	FeatureKnownProxies           = "C2_Known_Proxies"
	FeatureSmallPackets           = "C2_Small_Packets"
)
