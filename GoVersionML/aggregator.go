package main

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

// IPStats tracks all the raw data needed to compute our 21 Advanced XGBoost features.
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
	first, ok1 := parseTimestamp(record.First)
	if !ok1 {
		return // Skip records without valid timestamps
	}

	// 1. Process Outbound Perspective (Main Features)
	srcIP := record.Src4Addr
	if srcIP != "" {
		srcKey := getWindowKey(srcIP, first)
		stats, exists := a.IPs[srcKey]
		if !exists {
			stats = NewIPStats()
			stats.IP = srcIP
			a.IPs[srcKey] = stats
		}

		stats.FlowCount++
		stats.UniqueDstIPs[record.Dst4Addr] = true
		stats.UniqueDstPorts[record.DstPort] = true
		stats.OutboundDstPorts[record.DstPort] = true
		stats.TotalBytes += float64(record.InBytes)
		stats.TotalPackets += float64(record.InPackets)

		// Proto
		if record.Proto == 6 {
			stats.TCPCount++
		} else if record.Proto == 17 {
			stats.UDPCount++
		} else if record.Proto == 1 {
			stats.ICMPCount++
		}

		// Flags (Resilient SYN-only check)
		if strings.Contains(record.TCPFlags, "S") && !strings.ContainsAny(record.TCPFlags, "AFR") {
			stats.SynOnlyCount++
		}
		if strings.Contains(record.TCPFlags, "R") {
			stats.RstCount++
		}

		// Ports
		if record.DstPort < 1024 {
			stats.WellKnownPortCount++
		}

		// Timing
		last, ok2 := parseTimestamp(record.Last)
		// Track Start Time specifically for this Target (NetFlow v5 Periodic Beaconing fix)
		targetKey := fmt.Sprintf("%s:%d", record.Dst4Addr, record.DstPort)
		stats.TargetStartTimes[targetKey] = append(stats.TargetStartTimes[targetKey], float64(first.UnixNano())/1e9)

		if ok2 {
			duration := last.Sub(first).Seconds()
			if duration < 0 {
				duration = 0
			}
			stats.SumDurationSec += duration
		}
	}

	// 2. Process Inbound Perspective (For P2P Port Symmetry)
	dstIP := record.Dst4Addr
	if dstIP != "" {
		dstKey := getWindowKey(dstIP, first)
		dstStats, exists := a.IPs[dstKey]
		if !exists {
			dstStats = NewIPStats()
			dstStats.IP = dstIP
			a.IPs[dstKey] = dstStats
		}
		// FIX: Use DstPort instead of SrcPort since the peer is connecting TO this port
		dstStats.InboundDstPorts[record.DstPort] = true
	}
}

// Update processes a single netflow record, updating the IP ML tracker.
// func (a *Aggregator) Update(record models.NetflowRecord) {
// 	first, ok := parseTimestamp(record.First)
// 	if !ok {
// 		return // Skip records without valid timestamps
// 	}

// 	// 1. Process Outbound Perspective
// 	if record.Src4Addr != "" {
// 		srcStats := a.getOrCreateStats(record.Src4Addr, first)
// 		updateOutboundStats(srcStats, record, first)
// 	}

// 	// 2. Process Inbound Perspective
// 	if record.Dst4Addr != "" {
// 		dstStats := a.getOrCreateStats(record.Dst4Addr, first)
// 		updateInboundStats(dstStats, record)
// 	}
// }

// // getOrCreateStats handles the map lookup and initialization
// func (a *Aggregator) getOrCreateStats(ip string, ts time.Time) *IPStats {
// 	key := getWindowKey(ip, ts)
// 	stats, exists := a.IPs[key]
// 	if !exists {
// 		stats = NewIPStats()
// 		stats.IP = ip
// 		a.IPs[key] = stats
// 	}
// 	return stats
// }

// func updateOutboundStats(stats *IPStats, record models.NetflowRecord, first time.Time) {
// 	stats.FlowCount++
// 	stats.UniqueDstIPs[record.Dst4Addr] = true
// 	stats.UniqueDstPorts[record.DstPort] = true
// 	stats.OutboundDstPorts[record.DstPort] = true
// 	stats.TotalBytes += float64(record.InBytes)
// 	stats.TotalPackets += float64(record.InPackets)

// 	// Proto
// 	switch record.Proto {
// 	case 6:
// 		stats.TCPCount++
// 	case 17:
// 		stats.UDPCount++
// 	case 1:
// 		stats.ICMPCount++
// 	}

// 	// Flags (Resilient SYN-only check)
// 	if strings.Contains(record.TCPFlags, "S") && !strings.ContainsAny(record.TCPFlags, "AFR") {
// 		stats.SynOnlyCount++
// 	}
// 	if strings.Contains(record.TCPFlags, "R") {
// 		stats.RstCount++
// 	}

// 	// Ports
// 	if record.DstPort > 0 && record.DstPort < 1024 {
// 		stats.WellKnownPortCount++
// 	}

// 	// Timing & Beaconing (BUG FIXED)
// 	targetKey := fmt.Sprintf("%s:%d", record.Dst4Addr, record.DstPort)
// 	stats.TargetStartTimes[targetKey] = append(stats.TargetStartTimes[targetKey], float64(first.UnixNano())/1e9)

// 	if last, ok := parseTimestamp(record.Last); ok {
// 		duration := last.Sub(first).Seconds()
// 		if duration < 0 {
// 			duration = 0
// 		}
// 		stats.SumDurationSec += duration
// 	}
// }

// func updateInboundStats(stats *IPStats, record models.NetflowRecord) {
// 	// FIX: Use DstPort instead of SrcPort since the peer is connecting TO this port
// 	stats.InboundDstPorts[record.DstPort] = true
// }

// ToMLVector computes the final 21 float64 features expected by XGBoost V2.
func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 21) // Length matches V2 feature set
	}

	avgBytes := s.TotalBytes / fc
	avgPackets := s.TotalPackets / fc
	pctTCP := (s.TCPCount / fc) * 100.0
	pctUDP := (s.UDPCount / fc) * 100.0
	pctICMP := (s.ICMPCount / fc) * 100.0
	pctWellKnown := (s.WellKnownPortCount / fc) * 100.0
	pctHigh := 100.0 - pctWellKnown
	avgDuration := s.SumDurationSec / fc

	// V2: Port Symmetry
	var portSymmetry float64
	for p := range s.OutboundDstPorts {
		if s.InboundDstPorts[p] {
			portSymmetry++
		}
	}

	// V2: Horizontal/Vertical Scan Ratio
	uniquePorts := float64(len(s.UniqueDstPorts))
	if uniquePorts == 0 {
		uniquePorts = 1
	}
	ipPortRatio := float64(len(s.UniqueDstIPs)) / uniquePorts

	// V2: Payload Delivery Ratio
	totalPackets := s.TotalPackets
	if totalPackets == 0 {
		totalPackets = 1
	}
	avgPayload := s.TotalBytes / totalPackets

	// V2: Failure Rate Percentages
	pctSynOnly := (s.SynOnlyCount / fc) * 100.0
	pctRst := (s.RstCount / fc) * 100.0

	// V2: Periodicity CV (Target-based Flow IAT)
	var iatMean, iatVar, iatCV float64
	var allDiffs []float64

	for _, times := range s.TargetStartTimes {
		allDiffs = append(allDiffs, 0) // First flow in each target group gets 0 (matches Python fillna(0))
		if len(times) > 1 {
			sort.Float64s(times)
			for i := 1; i < len(times); i++ {
				allDiffs = append(allDiffs, times[i]-times[i-1])
			}
		}
	}

	if len(allDiffs) > 0 {
		var sumDiffs float64
		for _, d := range allDiffs {
			sumDiffs += d
		}
		iatMean = sumDiffs / float64(len(allDiffs))

		var sumSqDiff float64
		for _, d := range allDiffs {
			sumSqDiff += (d - iatMean) * (d - iatMean)
		}
		if len(allDiffs) > 1 {
			iatVar = sumSqDiff / float64(len(allDiffs)-1) // ddof=1, matches pandas default
		}

		if iatMean > 0 {
			iatCV = math.Sqrt(iatVar) / iatMean
		}
	}

	return []float64{
		fc,                             // 0
		float64(len(s.UniqueDstIPs)),   // 1
		float64(len(s.UniqueDstPorts)), // 2
		s.TotalBytes,                   // 3
		s.TotalPackets,                 // 4
		avgBytes,                       // 5
		avgPackets,                     // 6
		pctTCP,                         // 7
		pctUDP,                         // 8
		pctICMP,                        // 9
		pctWellKnown,                   // 10
		pctHigh,                        // 11
		avgDuration,                    // 12
		iatMean,                        // 13
		iatVar,                         // 14
		portSymmetry,                   // 15
		ipPortRatio,                    // 16
		avgPayload,                     // 17
		pctSynOnly,                     // 18
		pctRst,                         // 19
		iatCV,                          // 20
	}
}
