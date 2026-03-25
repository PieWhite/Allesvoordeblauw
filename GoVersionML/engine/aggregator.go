package engine

import (
	"hash/fnv"
	"log"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goversion/models"
)

type IPStats struct {
	IP                 string
	FlowCount          int
	UniqueDstIPs       map[string]struct{}
	UniqueDstPorts     map[int]struct{}
	OutboundDstPorts   map[int]struct{}
	InboundDstPorts    map[int]struct{}
	TotalBytes         float64
	TotalPackets       float64
	TCPCount           float64
	UDPCount           float64
	ICMPCount          float64
	SynOnlyCount       float64
	RstCount           float64
	WellKnownPortCount float64
	SumDurationSec     float64
	TargetStartTimes   map[TargetKey][]float64
}

func NewIPStats() *IPStats {
	return &IPStats{
		UniqueDstIPs:     make(map[string]struct{}),
		UniqueDstPorts:   make(map[int]struct{}),
		OutboundDstPorts: make(map[int]struct{}),
		InboundDstPorts:  make(map[int]struct{}),
		TargetStartTimes: make(map[TargetKey][]float64),
	}
}

type TargetKey struct {
	IP   string
	Port int
}

const numShards = 64

type WindowKey struct {
	IP     string
	Window int64
}

type Shard struct {
	sync.RWMutex
	IPs map[WindowKey]*IPStats
}

type Aggregator struct {
	shards                 [numShards]*Shard
	timestampWarningLogged atomic.Bool
}

func NewAggregator() *Aggregator {
	a := &Aggregator{}
	for i := 0; i < numShards; i++ {
		a.shards[i] = &Shard{
			IPs: make(map[WindowKey]*IPStats),
		}
	}
	return a
}

func (a *Aggregator) getShardIndex(key WindowKey) int {
	h := fnv.New32a()
	h.Write([]byte(key.IP))
	return int(h.Sum32()) & (numShards - 1)
}

func (a *Aggregator) parseTimestamp(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil && a.timestampWarningLogged.CompareAndSwap(false, true) {
		log.Printf("WARNING: failed to parse timestamp %q: %v (further warnings suppressed)", s, err)
	}
	return t, err == nil
}

func getWindowKey(ip string, t time.Time) WindowKey {
	return WindowKey{
		IP:     ip,
		Window: t.Truncate(5 * time.Minute).Unix(),
	}
}

func (a *Aggregator) Update(record models.NetflowRecord) {
	first, ok := a.parseTimestamp(record.First)
	if !ok {
		return
	}

	if record.Src4Addr != "" {
		key := getWindowKey(record.Src4Addr, first)
		shardIdx := a.getShardIndex(key)
		shard := a.shards[shardIdx]

		shard.Lock()
		stats, exists := shard.IPs[key]
		if !exists {
			stats = NewIPStats()
			stats.IP = record.Src4Addr
			shard.IPs[key] = stats
		}
		a.updateOutboundStats(stats, record, first)
		shard.Unlock()
	}

	if record.Dst4Addr != "" {
		key := getWindowKey(record.Dst4Addr, first)
		shardIdx := a.getShardIndex(key)
		shard := a.shards[shardIdx]

		shard.Lock()
		stats, exists := shard.IPs[key]
		if !exists {
			stats = NewIPStats()
			stats.IP = record.Dst4Addr
			shard.IPs[key] = stats
		}
		updateInboundStats(stats, record)
		shard.Unlock()
	}
}

// AllIPStats safely collects all IPStats across shards
func (a *Aggregator) AllIPStats() []*IPStats {
	var all []*IPStats
	for i := 0; i < numShards; i++ {
		shard := a.shards[i]
		shard.RLock()
		for _, stats := range shard.IPs {
			all = append(all, stats)
		}
		shard.RUnlock()
	}
	return all
}

func (a *Aggregator) updateOutboundStats(stats *IPStats, record models.NetflowRecord, first time.Time) {
	stats.FlowCount++
	stats.UniqueDstIPs[record.Dst4Addr] = struct{}{}
	stats.UniqueDstPorts[record.DstPort] = struct{}{}
	stats.OutboundDstPorts[record.DstPort] = struct{}{}
	stats.TotalBytes += float64(record.InBytes)
	stats.TotalPackets += float64(record.InPackets)

	switch record.Proto {
	case 6:
		stats.TCPCount++
	case 17:
		stats.UDPCount++
	case 1:
		stats.ICMPCount++
	}

	if strings.Contains(record.TCPFlags, "S") && !strings.ContainsAny(record.TCPFlags, "AFR") {
		stats.SynOnlyCount++
	}
	if strings.Contains(record.TCPFlags, "R") {
		stats.RstCount++
	}

	if record.DstPort < 1024 {
		stats.WellKnownPortCount++
	}

	a.updateTimingMetrics(stats, record, first)
}

func updateInboundStats(stats *IPStats, record models.NetflowRecord) {
	stats.InboundDstPorts[record.DstPort] = struct{}{}
}

func (a *Aggregator) updateTimingMetrics(s *IPStats, record models.NetflowRecord, first time.Time) {
	tKey := TargetKey{IP: record.Dst4Addr, Port: record.DstPort}
	s.TargetStartTimes[tKey] = append(s.TargetStartTimes[tKey], float64(first.UnixNano())/1e9)

	if last, ok := a.parseTimestamp(record.Last); ok {
		duration := last.Sub(first).Seconds()
		if duration < 0 {
			duration = 0
		}
		s.SumDurationSec += duration
	}
}

// ToMLVector computes the final 21 float64 features expected by XGBoost V2.
func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 21)
	}

	portSymmetry := s.calculatePortSymmetry()
	iatMean, iatVar, iatCV := s.calculateIATMetrics()

	uniquePorts := float64(len(s.UniqueDstPorts))
	if uniquePorts == 0 {
		uniquePorts = 1
	}

	totalPackets := s.TotalPackets
	if totalPackets == 0 {
		totalPackets = 1
	}

	pctWellKnownPorts := (s.WellKnownPortCount / fc) * 100.0

	//Pack and return the array — order matches extract_features_v2.py
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
		pctWellKnownPorts,              // 10: pct_well_known_ports
		100.0 - pctWellKnownPorts,      // 11: pct_high_ports
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

func (s *IPStats) calculatePortSymmetry() float64 {
	var symmetry float64
	for p := range s.OutboundDstPorts {
		if _, ok := s.InboundDstPorts[p]; ok {
			symmetry++
		}
	}
	return symmetry
}

func (s *IPStats) calculateIATMetrics() (mean float64, variance float64, cv float64) {
	totalItems := len(s.TargetStartTimes) // for the fillna(0) zeros
	for _, times := range s.TargetStartTimes {
		if len(times) > 1 {
			totalItems += len(times) - 1
		}
	}

	allDiffs := make([]float64, 0, totalItems)

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

	var sumDiffs float64
	for _, d := range allDiffs {
		sumDiffs += d
	}
	mean = sumDiffs / float64(len(allDiffs))

	// (ddof=1, matches pandas .var() default)
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
