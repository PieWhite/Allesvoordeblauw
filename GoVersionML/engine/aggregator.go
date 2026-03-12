package engine

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"

	"goversion/models"
)

var timestampWarningLogged bool

func parseTimestamp(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil && !timestampWarningLogged {
		log.Printf("WARNING: failed to parse timestamp %q: %v (further warnings suppressed)", s, err)
		timestampWarningLogged = true
	}
	return t, err == nil
}

// Helper to chunk data into 5-minute time windows like Python
func getWindowKey(ip string, t time.Time) string {
	// Floor to 5 minute chunks
	window := t.Truncate(5 * time.Minute).Unix()
	return fmt.Sprintf("%s|%d", ip, window)
}

// IPStats tracks all the raw data needed to compute our 21 Advanced XGBoost V2 features.
type IPStats struct {
	IP                 string
	FlowCount          int
	UniqueDstIPs       map[string]bool
	UniqueDstPorts     map[int]bool
	OutboundDstPorts   map[int]bool
	InboundDstPorts    map[int]bool
	TotalBytes         float64
	TotalPackets       float64
	TCPCount           float64
	UDPCount           float64
	ICMPCount          float64
	SynOnlyCount       float64
	RstCount           float64
	WellKnownPortCount float64
	SumDurationSec     float64
	TargetStartTimes   map[string][]float64 // Tracks timestamps grouped by DstIP:DstPort
}

// NewIPStats creates a ready-to-use IPStats
func NewIPStats() *IPStats {
	return &IPStats{
		UniqueDstIPs:     make(map[string]bool),
		UniqueDstPorts:   make(map[int]bool),
		OutboundDstPorts: make(map[int]bool),
		InboundDstPorts:  make(map[int]bool),
		TargetStartTimes: make(map[string][]float64),
	}
}

// Aggregator accumulates states per IP to build ML vectors
type Aggregator struct {
	IPs map[string]*IPStats
}

// NewAggregator creates an empty Aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		IPs: make(map[string]*IPStats),
	}
}

// Update processes a single netflow record, updating the IP ML tracker.
func (a *Aggregator) Update(record models.NetflowRecord) {
	first, ok := parseTimestamp(record.First)
	if !ok {
		return // Skip records without valid timestamps
	}

	// 1. Process Outbound Perspective
	if record.Src4Addr != "" {
		srcStats := a.getOrCreateStats(record.Src4Addr, first)
		updateOutboundStats(srcStats, record, first)
	}

	// 2. Process Inbound Perspective
	if record.Dst4Addr != "" {
		dstStats := a.getOrCreateStats(record.Dst4Addr, first)
		updateInboundStats(dstStats, record)
	}
}

// getOrCreateStats handles the map lookup and initialization
func (a *Aggregator) getOrCreateStats(ip string, ts time.Time) *IPStats {
	key := getWindowKey(ip, ts)
	stats, exists := a.IPs[key]
	if !exists {
		stats = NewIPStats()
		stats.IP = ip
		a.IPs[key] = stats
	}
	return stats
}

func updateOutboundStats(stats *IPStats, record models.NetflowRecord, first time.Time) {
	stats.FlowCount++
	stats.UniqueDstIPs[record.Dst4Addr] = true
	stats.UniqueDstPorts[record.DstPort] = true
	stats.OutboundDstPorts[record.DstPort] = true
	stats.TotalBytes += float64(record.InBytes)
	stats.TotalPackets += float64(record.InPackets)

	// Proto
	switch record.Proto {
	case 6:
		stats.TCPCount++
	case 17:
		stats.UDPCount++
	case 1:
		stats.ICMPCount++
	}

	// Flags (Resilient SYN-only check)
	if strings.Contains(record.TCPFlags, "S") && !strings.ContainsAny(record.TCPFlags, "AFR") {
		stats.SynOnlyCount++
	}
	if strings.Contains(record.TCPFlags, "R") {
		stats.RstCount++
	}

	// Ports (matches Python: dst_port < 1024)
	if record.DstPort < 1024 {
		stats.WellKnownPortCount++
	}

	// Timing & Beaconing
	targetKey := fmt.Sprintf("%s:%d", record.Dst4Addr, record.DstPort)
	stats.TargetStartTimes[targetKey] = append(stats.TargetStartTimes[targetKey], float64(first.UnixNano())/1e9)

	if last, ok := parseTimestamp(record.Last); ok {
		duration := last.Sub(first).Seconds()
		if duration < 0 {
			duration = 0
		}
		stats.SumDurationSec += duration
	}
}

func updateInboundStats(stats *IPStats, record models.NetflowRecord) {
	// Use DstPort since the peer is connecting TO this port
	stats.InboundDstPorts[record.DstPort] = true
}

// ToMLVector computes the final 21 float64 features expected by XGBoost V2.
func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 21) // Length matches V2 feature set
	}

	// 1. Delegate the complex math to our helpers
	portSymmetry := s.calculatePortSymmetry()
	iatMean, iatVar, iatCV := s.calculateIATMetrics()

	// 2. Calculate simple inline ratios
	uniquePorts := float64(len(s.UniqueDstPorts))
	if uniquePorts == 0 {
		uniquePorts = 1
	}

	totalPackets := s.TotalPackets
	if totalPackets == 0 {
		totalPackets = 1
	}

	pctWellKnown := (s.WellKnownPortCount / fc) * 100.0

	// 3. Pack and return the array — order matches extract_features_v2.py features_to_keep
	return []float64{
		fc,                             // 0:  flow_count
		float64(len(s.UniqueDstIPs)),   // 1:  unique_dst_ips
		float64(len(s.UniqueDstPorts)), // 2:  unique_dst_ports
		s.TotalBytes,                   // 3:  total_bytes
		s.TotalPackets,                 // 4:  total_packets
		s.TotalBytes / fc,              // 5:  avg_bytes_per_flow
		s.TotalPackets / fc,            // 6:  avg_packets_per_flow
		(s.TCPCount / fc) * 100.0,      // 7:  pct_tcp
		(s.UDPCount / fc) * 100.0,      // 8:  pct_udp
		(s.ICMPCount / fc) * 100.0,     // 9:  pct_icmp
		pctWellKnown,                   // 10: pct_well_known_ports
		100.0 - pctWellKnown,           // 11: pct_high_ports
		s.SumDurationSec / fc,          // 12: avg_duration
		iatMean,                        // 13: iat_mean
		iatVar,                         // 14: iat_variance
		portSymmetry,                   // 15: port_symmetry
		float64(len(s.UniqueDstIPs)) / uniquePorts, // 16: ip_port_ratio
		s.TotalBytes / totalPackets,                // 17: avg_payload_per_packet
		(s.SynOnlyCount / fc) * 100.0,              // 18: pct_syn_only
		(s.RstCount / fc) * 100.0,                  // 19: pct_rst
		iatCV,                                      // 20: iat_cv
	}
}

// calculatePortSymmetry finds instances where the IP acts as both client and server on the same port
func (s *IPStats) calculatePortSymmetry() float64 {
	var symmetry float64
	for p := range s.OutboundDstPorts {
		if s.InboundDstPorts[p] {
			symmetry++
		}
	}
	return symmetry
}

// calculateIATMetrics computes the Mean, Variance (ddof=1), and CV of inter-arrival times.
// Matches Python pipeline: first flow per target group gets 0 (fillna(0)), variance uses ddof=1.
func (s *IPStats) calculateIATMetrics() (mean float64, variance float64, cv float64) {
	var allDiffs []float64

	for _, times := range s.TargetStartTimes {
		allDiffs = append(allDiffs, 0) // Match Python fillna(0)
		if len(times) > 1 {
			sort.Float64s(times)
			for i := 1; i < len(times); i++ {
				allDiffs = append(allDiffs, times[i]-times[i-1])
			}
		}
	}

	if len(allDiffs) == 0 {
		return 0, 0, 0
	}

	// Calculate Mean
	var sumDiffs float64
	for _, d := range allDiffs {
		sumDiffs += d
	}
	mean = sumDiffs / float64(len(allDiffs))

	// Calculate Variance (ddof=1, matches pandas .var() default)
	var sumSqDiff float64
	for _, d := range allDiffs {
		sumSqDiff += (d - mean) * (d - mean)
	}
	if len(allDiffs) > 1 {
		variance = sumSqDiff / float64(len(allDiffs)-1)
	}

	// Calculate CV
	if mean > 0 {
		cv = math.Sqrt(variance) / mean
	}

	return mean, variance, cv
}
