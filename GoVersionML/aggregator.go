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

// IPStats tracks all the raw data needed to compute our 26 Advanced XGBoost V3 features.
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

	// V3 fields
	BytesList        []float64      // Per-flow byte values (for std dev)
	PacketsList      []float64      // Per-flow packet values (for std dev)
	SmallPacketCount float64        // Flows with in_packets <= 3
	DstIPFlowCounts  map[string]int // Per-destination-IP flow count (for Shannon entropy)
	WindowFirstFlow  time.Time      // Earliest 'first' timestamp in window
	WindowLastFlow   time.Time      // Latest 'last' timestamp in window
}

// NewIPStats creates a ready-to-use IPStats
func NewIPStats() *IPStats {
	return &IPStats{
		UniqueDstIPs:     make(map[string]bool),
		UniqueDstPorts:   make(map[int]bool),
		OutboundDstPorts: make(map[int]bool),
		InboundDstPorts:  make(map[int]bool),
		TargetStartTimes: make(map[string][]float64),
		DstIPFlowCounts:  make(map[string]int),
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

		// V3: Track per-flow values for std dev calculation
		stats.BytesList = append(stats.BytesList, float64(record.InBytes))
		stats.PacketsList = append(stats.PacketsList, float64(record.InPackets))

		// V3: Small packet detection (Mirai scan probes are typically 1-3 packets)
		if record.InPackets <= 3 {
			stats.SmallPacketCount++
		}

		// V3: Track per-destination flow count for Shannon entropy
		stats.DstIPFlowCounts[record.Dst4Addr]++

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

		// V3: Track window time boundaries for flow_rate
		if stats.WindowFirstFlow.IsZero() || first.Before(stats.WindowFirstFlow) {
			stats.WindowFirstFlow = first
		}

		if ok2 {
			if stats.WindowLastFlow.IsZero() || last.After(stats.WindowLastFlow) {
				stats.WindowLastFlow = last
			}
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

// sampleStdDev computes sample standard deviation (ddof=1) to match pandas .std() default.
// Returns 0 when fewer than 2 values (matches pandas fillna(0) for single-flow groups).
func sampleStdDev(vals []float64) float64 {
	n := len(vals)
	if n < 2 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(n)
	var sumSq float64
	for _, v := range vals {
		d := v - mean
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(n-1))
}

// shannonEntropy computes the Shannon entropy (log base 2) of a frequency distribution.
func shannonEntropy(counts map[string]int) float64 {
	var total float64
	for _, c := range counts {
		total += float64(c)
	}
	if total == 0 {
		return 0
	}
	var entropy float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ToMLVector computes the final 26 float64 features expected by XGBoost V3.
func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 26) // Length matches V3 feature set
	}

	avgBytes := s.TotalBytes / fc
	avgPackets := s.TotalPackets / fc
	pctTCP := (s.TCPCount / fc) * 100.0
	pctUDP := (s.UDPCount / fc) * 100.0
	pctICMP := (s.ICMPCount / fc) * 100.0
	pctWellKnown := (s.WellKnownPortCount / fc) * 100.0
	pctHigh := 100.0 - pctWellKnown
	avgDuration := s.SumDurationSec / fc

	// V3: Byte/Packet Standard Deviation (ddof=1, matches pandas)
	bytesStd := sampleStdDev(s.BytesList)
	packetsStd := sampleStdDev(s.PacketsList)

	// V3: Flow Rate (flows per second of active window duration)
	var flowRate float64
	windowDuration := s.WindowLastFlow.Sub(s.WindowFirstFlow).Seconds()
	if windowDuration < 1 {
		windowDuration = 1 // clip(lower=1) matches Python
	}
	flowRate = fc / windowDuration

	// V3: Small Packet Ratio
	pctSmallPacket := (s.SmallPacketCount / fc) * 100.0

	// V3: Destination IP Shannon Entropy
	dstIPEntropy := shannonEntropy(s.DstIPFlowCounts)

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

	// V3 feature order — matches extract_features_v3.py features_to_keep exactly
	return []float64{
		fc,                             // 0  flow_count
		float64(len(s.UniqueDstIPs)),   // 1  unique_dst_ips
		float64(len(s.UniqueDstPorts)), // 2  unique_dst_ports
		s.TotalBytes,                   // 3  total_bytes
		s.TotalPackets,                 // 4  total_packets
		avgBytes,                       // 5  avg_bytes_per_flow
		avgPackets,                     // 6  avg_packets_per_flow
		bytesStd,                       // 7  bytes_std          (V3 NEW)
		packetsStd,                     // 8  packets_std        (V3 NEW)
		flowRate,                       // 9  flow_rate          (V3 NEW)
		pctSmallPacket,                 // 10 pct_small_packet   (V3 NEW)
		dstIPEntropy,                   // 11 dst_ip_entropy     (V3 NEW)
		pctTCP,                         // 12 pct_tcp
		pctUDP,                         // 13 pct_udp
		pctICMP,                        // 14 pct_icmp
		pctWellKnown,                   // 15 pct_well_known_ports
		pctHigh,                        // 16 pct_high_ports
		avgDuration,                    // 17 avg_duration
		iatMean,                        // 18 iat_mean
		iatVar,                         // 19 iat_variance
		portSymmetry,                   // 20 port_symmetry
		ipPortRatio,                    // 21 ip_port_ratio
		avgPayload,                     // 22 avg_payload_per_packet
		pctSynOnly,                     // 23 pct_syn_only
		pctRst,                         // 24 pct_rst
		iatCV,                          // 25 iat_cv
	}
}
