package main

// RuleContext bundles all inputs that a detection rule might need.
// This avoids a long parameter list and eliminates unused _ placeholders.
type RuleContext struct {
	SrcIP   string
	Record  NetflowRecord
	Agg     RecordAggregator
	Config  *Config
	Lookups *Lookups
}

// RuleFunc is the signature for all detection rules.
// Each rule receives a context and returns whether it triggered and the feature name.
type RuleFunc func(ctx *RuleContext) (triggered bool, featureName string)

// AllRules returns all detection rules in evaluation order.
// Adding a new rule is as simple as appending another function to this slice.
func AllRules() []RuleFunc {
	return []RuleFunc{
		checkFrequencyOfConnections,
		checkIPReuse,
		checkP2PCommunications,
		checkPacketSizeAnomalies,
		checkKnownProxies,
		checkSuspiciousPorts,
		checkSmallPackets,
	}
}

// --- Simple rules (single-record evaluation) ---

// checkFrequencyOfConnections flags IPs that exceed the connection count threshold.
func checkFrequencyOfConnections(ctx *RuleContext) (bool, string) {
	if ctx.Agg.ConnectionCount(ctx.SrcIP) > ctx.Config.Thresholds.FrequencyOfConnections {
		return true, FeatureFrequencyOfConnections
	}
	return false, ""
}

// checkIPReuse flags IPs that repeatedly connect to the same destination.
func checkIPReuse(ctx *RuleContext) (bool, string) {
	if ctx.Record.Dst4Addr != "" && ctx.Agg.IPReuseCount(ctx.SrcIP, ctx.Record.Dst4Addr) > ctx.Config.Thresholds.IPReuseConnections {
		return true, FeatureIPReuse
	}
	return false, ""
}

// checkP2PCommunications flags IPs communicating with too many unique peers.
func checkP2PCommunications(ctx *RuleContext) (bool, string) {
	if ctx.Record.Dst4Addr != "" && ctx.Agg.UniquePeerCount(ctx.SrcIP) > ctx.Config.Thresholds.P2PUniquePeers {
		return true, FeatureP2P
	}
	return false, ""
}

// checkPacketSizeAnomalies flags IPs with suspicious data transfer patterns.
// It triggers on EITHER of two conditions:
//   1. High volume: the IP has more than PacketSizeAnomalyMinFlows data-carrying
//      flows (catches botnet C2 traffic with heavy communication patterns)
//   2. Small packets: the IP has at least 10 data flows AND the average bytes/flow
//      is below PacketSizeAnomalyAvgBytes (catches C2 beaconing with tiny
//      keepalive/heartbeat packets)
//
// HISTORY: The original Python version (detect_packet_size_anomalies) only checked
// condition 1 — counting flows with bytes and triggering if count > 1000. This was
// effectively a redundant frequency check with a misleading name. This Go version
// keeps that behavior (since those IPs were confirmed botnet members) but adds
// genuine packet size analysis (condition 2) to also catch beaconing patterns
// that the Python version would have missed.
//
// RESULT IMPACT vs Python: The top-tier IPs (98.06%) remain unchanged since they
// easily exceed the flow count threshold (condition 1). However, more IPs now
// appear at the 49.68% tier than in the Python output. These are IPs that have
// fewer than PacketSizeAnomalyMinFlows data flows but whose average bytes/flow
// is suspiciously small (< PacketSizeAnomalyAvgBytes). In the Python version
// these IPs only scored Frequency + IP Reuse (1.29%), but the new condition 2
// correctly identifies their small-packet traffic as anomalous — a hallmark of
// C2 beaconing where bots send minimal keepalive packets to maintain connections.
// This is an intentional improvement: these IPs are genuinely more suspicious
// than the Python version indicated.
func checkPacketSizeAnomalies(ctx *RuleContext) (bool, string) {
	flows := ctx.Agg.PacketSizeFlows(ctx.SrcIP)
	th := ctx.Config.Thresholds

	// Condition 1: High volume of data flows (original Python behavior)
	if flows > th.PacketSizeAnomalyMinFlows {
		return true, FeaturePacketSize
	}

	// Condition 2: Enough flows with anomalously small average packet size (new)
	if flows >= 10 && flows > 0 {
		avgBytesPerFlow := ctx.Agg.TotalBytes(ctx.SrcIP) / int64(flows)
		if avgBytesPerFlow < th.PacketSizeAnomalyAvgBytes {
			return true, FeaturePacketSize
		}
	}

	return false, ""
}

// checkKnownProxies flags traffic involving known C2 IP addresses.
func checkKnownProxies(ctx *RuleContext) (bool, string) {
	if ctx.Lookups.KnownC2IPSet[ctx.SrcIP] || ctx.Lookups.KnownC2IPSet[ctx.Record.Dst4Addr] {
		return true, FeatureKnownProxies
	}
	return false, ""
}

// --- Compound rules (evaluate accumulated pairState) ---

// checkSuspiciousPorts fires when a pair uses a suspicious port AND has enough
// connections within a short time window.
func checkSuspiciousPorts(ctx *RuleContext) (bool, string) {
	if ctx.Record.Dst4Addr == "" {
		return false, ""
	}
	ps := ctx.Agg.PairState(ctx.SrcIP, ctx.Record.Dst4Addr)
	if ps == nil {
		return false, ""
	}
	timeWindow := ps.lastSeen.Sub(ps.firstSeen).Seconds()
	if ps.hasSuspiciousPort &&
		ps.count > ctx.Config.Thresholds.SuspiciousPortConnCount &&
		timeWindow < ctx.Config.Thresholds.SuspiciousPortTimeWindow {
		return true, FeatureSuspiciousPorts
	}
	return false, ""
}

// checkSmallPackets fires when a pair has small average packets AND enough
// connections within a short time window.
func checkSmallPackets(ctx *RuleContext) (bool, string) {
	if ctx.Record.Dst4Addr == "" {
		return false, ""
	}
	ps := ctx.Agg.PairState(ctx.SrcIP, ctx.Record.Dst4Addr)
	if ps == nil {
		return false, ""
	}
	timeWindow := ps.lastSeen.Sub(ps.firstSeen).Seconds()
	if ps.hasSmallPackets &&
		ps.count > ctx.Config.Thresholds.BehavioralConnCount &&
		timeWindow < ctx.Config.Thresholds.BehavioralTimeWindow {
		return true, FeatureSmallPackets
	}
	return false, ""
}
