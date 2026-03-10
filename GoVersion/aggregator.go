package main

import (
	"log"
	"time"
)

// timestampWarningLogged ensures we only log one warning for timestamp parse failures.
var timestampWarningLogged bool

// parseTimestamp parses a netflow timestamp string into a time.Time.
// Logs a warning on the first failure to help diagnose silent compound-rule breakage.
func parseTimestamp(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil && !timestampWarningLogged {
		log.Printf("WARNING: failed to parse timestamp %q: %v (further warnings suppressed)", s, err)
		timestampWarningLogged = true
	}
	return t, err == nil
}

// Aggregator manages per-IP and per-pair state accumulated across netflow records.
type Aggregator struct {
	connectionCount map[string]int             // src_ip → total flow count
	ipReuse         map[string]map[string]int  // src_ip → dst_ip → count
	peerConnections map[string]map[string]bool // src_ip → set of unique dst_ips
	pairTracking    map[string]*pairState      // "src→dst" → compound rule state
}

// NewAggregator creates an empty Aggregator with all maps initialized.
func NewAggregator() *Aggregator {
	return &Aggregator{
		connectionCount: make(map[string]int),
		ipReuse:         make(map[string]map[string]int),
		peerConnections: make(map[string]map[string]bool),
		pairTracking:    make(map[string]*pairState),
	}
}

// Update processes a single netflow record, updating all aggregation state.
func (a *Aggregator) Update(record NetflowRecord) {
	srcIP := record.Src4Addr
	if srcIP == "" {
		return
	}
	dstIP := record.Dst4Addr

	// Connection frequency
	a.connectionCount[srcIP]++

	// IP reuse tracking
	if dstIP != "" {
		if a.ipReuse[srcIP] == nil {
			a.ipReuse[srcIP] = make(map[string]int)
		}
		a.ipReuse[srcIP][dstIP]++

		// Unique peer tracking
		if a.peerConnections[srcIP] == nil {
			a.peerConnections[srcIP] = make(map[string]bool)
		}
		a.peerConnections[srcIP][dstIP] = true
	}

}

// UpdatePairState updates or creates the compound-rule state for a src→dst pair.
// Returns the updated pairState for further evaluation by rules.
func (a *Aggregator) UpdatePairState(record NetflowRecord, isSuspiciousPort bool, isSmallPacket bool) *pairState {
	srcIP := record.Src4Addr
	dstIP := record.Dst4Addr
	if srcIP == "" || dstIP == "" {
		return nil
	}

	pairKey := srcIP + "->" + dstIP
	ps := a.pairTracking[pairKey]
	if ps == nil {
		ps = &pairState{}
		a.pairTracking[pairKey] = ps
	}
	ps.count++

	// Track timestamps
	if ts, ok := parseTimestamp(record.First); ok {
		if ps.firstSeen.IsZero() || ts.Before(ps.firstSeen) {
			ps.firstSeen = ts
		}
		if ts.After(ps.lastSeen) {
			ps.lastSeen = ts
		}
	}
	if ts, ok := parseTimestamp(record.Last); ok {
		if ts.After(ps.lastSeen) {
			ps.lastSeen = ts
		}
	}

	// Track compound flags
	if isSuspiciousPort {
		ps.hasSuspiciousPort = true
	}
	if isSmallPacket {
		ps.hasSmallPackets = true
	}

	return ps
}

// --- Query methods ---

// ConnectionCount returns the total flow count for a source IP.
func (a *Aggregator) ConnectionCount(srcIP string) int {
	return a.connectionCount[srcIP]
}

// IPReuseCount returns how many times src has connected to dst.
func (a *Aggregator) IPReuseCount(srcIP, dstIP string) int {
	if a.ipReuse[srcIP] == nil {
		return 0
	}
	return a.ipReuse[srcIP][dstIP]
}

// UniquePeerCount returns how many unique destination IPs a source has contacted.
func (a *Aggregator) UniquePeerCount(srcIP string) int {
	return len(a.peerConnections[srcIP])
}

// PairState returns the compound-rule state for a src→dst pair, or nil if unseen.
func (a *Aggregator) PairState(srcIP, dstIP string) *pairState {
	return a.pairTracking[srcIP+"->"+dstIP]
}
