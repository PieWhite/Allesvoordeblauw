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
