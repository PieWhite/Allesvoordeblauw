package main

// Feature name constants used by rules and the scorer.
// Centralised here to eliminate magic strings and ensure compile-time safety.
const (
	FeatureFrequencyOfConnections = "Frequency_Of_Connections"
	FeatureIPReuse                = "IP_Reuse_Repeated_Connections"
	FeatureP2P                    = "P2P_C2_Communications"
	FeatureSuspiciousPorts        = "C2_Suspicious_Ports"
	FeatureKnownProxies           = "C2_Known_Proxies"
	FeatureSmallPackets           = "C2_Small_Packets"
)
