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
	UniqueSrcPorts     map[int]struct{} // V5 feature
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

	// V5 New metrics
	DstIPFreq            map[string]int
	SrcPortFreq          map[int]int
	DstPortFreq          map[int]int
	BppRatios            []float32
	BppRoundedFreq       map[float64]int
	MinuteBuckets        map[int64]int

	MeanBytes            float64
	M2Bytes              float64
	MeanPackets          float64
	M2Packets            float64
	MeanBpp              float64
	M2Bpp                float64

	SrcEphemeralCount    float64
	SrcWellKnownCount    float64
	ClientInitiatedCount float64
	ServerInitiatedCount float64
}

func NewIPStats() *IPStats {
	return &IPStats{
		UniqueDstIPs:     make(map[string]struct{}),
		UniqueDstPorts:   make(map[int]struct{}),
		UniqueSrcPorts:   make(map[int]struct{}),
		OutboundDstPorts: make(map[int]struct{}),
		InboundDstPorts:  make(map[int]struct{}),
		TargetStartTimes: make(map[TargetKey][]float64),

		DstIPFreq:      make(map[string]int),
		SrcPortFreq:    make(map[int]int),
		DstPortFreq:    make(map[int]int),
		BppRatios:      make([]float32, 0),
		BppRoundedFreq: make(map[float64]int),
		MinuteBuckets:  make(map[int64]int),
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
	if len(s) >= 23 && s[4] == '-' && s[10] == 'T' {
		year := int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
		month := int(s[5]-'0')*10 + int(s[6]-'0')
		day := int(s[8]-'0')*10 + int(s[9]-'0')
		hour := int(s[11]-'0')*10 + int(s[12]-'0')
		minute := int(s[14]-'0')*10 + int(s[15]-'0')
		second := int(s[17]-'0')*10 + int(s[18]-'0')
		msec := int(s[20]-'0')*100 + int(s[21]-'0')*10 + int(s[22]-'0')
		return time.Date(year, time.Month(month), day, hour, minute, second, msec*1000000, time.UTC), true
	}

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
	stats.UniqueSrcPorts[record.SrcPort] = struct{}{} // V5
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

	// V5 Feature engineering Additions
	stats.DstIPFreq[record.Dst4Addr]++
	stats.SrcPortFreq[record.SrcPort]++
	stats.DstPortFreq[record.DstPort]++

	if record.SrcPort >= 49152 {
		stats.SrcEphemeralCount++
	}
	if record.SrcPort < 1024 {
		stats.SrcWellKnownCount++
	}
	if record.SrcPort >= 49152 && record.DstPort < 1024 {
		stats.ClientInitiatedCount++
	}
	if record.SrcPort < 1024 && record.DstPort >= 49152 {
		stats.ServerInitiatedCount++
	}

	// Minute bucket for burst max flows
	minBucket := first.Truncate(time.Minute).Unix()
	stats.MinuteBuckets[minBucket]++

	// Bpp ratio
	denom := float64(record.InPackets)
	if denom == 0 {
		denom = 1
	}
	bpp := float64(record.InBytes) / denom

	if len(stats.BppRatios) < 25000 {
		stats.BppRatios = append(stats.BppRatios, float32(bpp))
	}

	bppRounded := math.Round(bpp*1000) / 1000
	stats.BppRoundedFreq[bppRounded]++

	// Welford's Method for Bytes, Packets, Bpp Std calculation
	bytesFl := float64(record.InBytes)
	packFl := float64(record.InPackets)

	deltaBytes := bytesFl - stats.MeanBytes
	stats.MeanBytes += deltaBytes / float64(stats.FlowCount)
	stats.M2Bytes += deltaBytes * (bytesFl - stats.MeanBytes)

	deltaPack := packFl - stats.MeanPackets
	stats.MeanPackets += deltaPack / float64(stats.FlowCount)
	stats.M2Packets += deltaPack * (packFl - stats.MeanPackets)

	deltaBpp := bpp - stats.MeanBpp
	stats.MeanBpp += deltaBpp / float64(stats.FlowCount)
	stats.M2Bpp += deltaBpp * (bpp - stats.MeanBpp)

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

// ToMLVector computes the final 36 float64 features expected by XGBoost V5.
func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 36)
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

	// Entropies
	dstIPEntropy := calculateEntropy(s.DstIPFreq, fc)
	srcPortEntropy := calculateIntEntropy(s.SrcPortFreq, fc)

	// Top port share
	var maxDstPortFreq int
	for _, count := range s.DstPortFreq {
		if count > maxDstPortFreq {
			maxDstPortFreq = count
		}
	}
	topDstPortSharePct := (float64(maxDstPortFreq) / fc) * 100.0

	// Burst Max
	var burstMax float64
	for _, count := range s.MinuteBuckets {
		if float64(count) > burstMax {
			burstMax = float64(count)
		}
	}

	// IQRs and Std
	bppIqr := calculateBPPIQR(&s.BppRatios)
	domP75 := dominantBPPCount(s.BppRoundedFreq, int(fc), 0.75)
	domP90 := dominantBPPCount(s.BppRoundedFreq, int(fc), 0.90)

	bytesStd := 0.0
	packetsStd := 0.0
	bppStd := 0.0
	if fc > 1 {
		bytesStd = math.Sqrt(s.M2Bytes / (fc - 1))
		packetsStd = math.Sqrt(s.M2Packets / (fc - 1))
		bppStd = math.Sqrt(s.M2Bpp / (fc - 1))
	}

	//Pack and return the array — order matches extract_features_v5.py
	return []float64{
		fc / 300.0,                                     // 0: flows_per_second
		s.TotalBytes / 300.0,                           // 1: bytes_per_second
		s.TotalPackets / 300.0,                         // 2: packets_per_second
		float64(len(s.UniqueDstIPs)),                   // 3: unique_dst_ips
		float64(len(s.UniqueDstPorts)),                 // 4: unique_dst_ports
		float64(len(s.UniqueSrcPorts)),                 // 5: unique_src_ports
		s.TotalBytes / fc,                              // 6: avg_bytes_per_flow
		s.TotalPackets / fc,                            // 7: avg_packets_per_flow
		bytesStd,                                       // 8: bytes_std
		packetsStd,                                     // 9: packets_std
		bppStd,                                         // 10: bpp_std
		bppIqr,                                         // 11: bpp_iqr
		dstIPEntropy,                                   // 12: dst_ip_entropy
		srcPortEntropy,                                 // 13: src_port_entropy
		topDstPortSharePct,                             // 14: top_dst_port_share_pct
		float64(domP75),                                // 15: dominant_bpp_count_p75
		float64(domP90),                                // 16: dominant_bpp_count_p90
		(s.TCPCount / fc) * 100.0,                      // 17: pct_tcp
		(s.UDPCount / fc) * 100.0,                      // 18: pct_udp
		(s.ICMPCount / fc) * 100.0,                     // 19: pct_icmp
		(s.WellKnownPortCount / fc) * 100.0,            // 20: pct_well_known_ports
		100.0 - ((s.WellKnownPortCount / fc) * 100.0),  // 21: pct_high_ports
		(s.SrcEphemeralCount / fc) * 100.0,             // 22: pct_ephemeral_src_ports
		(s.SrcWellKnownCount / fc) * 100.0,             // 23: pct_well_known_src_ports
		(s.ClientInitiatedCount / fc) * 100.0,          // 24: pct_client_initiated
		(s.ServerInitiatedCount / fc) * 100.0,          // 25: pct_server_initiated
		s.SumDurationSec / fc,                          // 26: avg_duration
		iatMean,                                        // 27: iat_mean
		iatVar,                                         // 28: iat_variance
		iatCV,                                          // 29: iat_cv
		portSymmetry,                                   // 30: port_symmetry
		float64(len(s.UniqueDstIPs)) / uniquePorts,     // 31: ip_port_ratio
		s.TotalBytes / totalPackets,                    // 32: avg_payload_per_packet
		(s.SynOnlyCount / fc) * 100.0,                  // 33: pct_syn_only
		(s.RstCount / fc) * 100.0,                      // 34: pct_rst
		burstMax,                                       // 35: burst_max_flows_per_min
	}
}

// Helpers
func calculateEntropy(freqs map[string]int, total float64) float64 {
	if total <= 0 {
		return 0.0
	}
	entropy := 0.0
	for _, count := range freqs {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func calculateIntEntropy(freqs map[int]int, total float64) float64 {
	if total <= 0 {
		return 0.0
	}
	entropy := 0.0
	for _, count := range freqs {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// calculateBPPIQR calculates the IQR (P75 - P25) of BppRatios.
// TODO: For future memory safety during extremely large volumetric attacks, replace
// the raw []float32 array with an approximate quantile sketch like T-Digest or 
// use a fixed-width histogram to compute IQRs without capping array lengths.
func calculateBPPIQR(bppRatios *[]float32) float64 {
	n := len(*bppRatios)
	if n < 2 {
		return 0.0
	}
	sort.Slice(*bppRatios, func(i, j int) bool {
		return (*bppRatios)[i] < (*bppRatios)[j]
	})
	
	q25Idx := int(float64(n-1) * 0.25)
	q75Idx := int(float64(n-1) * 0.75)
	
	return float64((*bppRatios)[q75Idx] - (*bppRatios)[q25Idx])
}

// dominantBPPCount calculates how many unique rounded BPP values constitute 'coverage' of total flows.
func dominantBPPCount(bppFreq map[float64]int, totalFlows int, coverage float64) int {
	if len(bppFreq) == 0 || totalFlows == 0 {
		return 0
	}
	
	counts := make([]int, 0, len(bppFreq))
	for _, count := range bppFreq {
		counts = append(counts, count)
	}
	
	sort.Sort(sort.Reverse(sort.IntSlice(counts)))
	
	cumulative := 0
	target := int(float64(totalFlows) * coverage)
	
	for i, count := range counts {
		cumulative += count
		if cumulative >= target {
			return i + 1
		}
	}
	return len(counts)
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

// ExtractAndFlushBefore removes and returns all IPStats from windows older than the specified timestamp
func (a *Aggregator) ExtractAndFlushBefore(window int64) []*IPStats {
	var flushed []*IPStats
	for i := 0; i < numShards; i++ {
		shard := a.shards[i]
		shard.Lock()
		for key, stats := range shard.IPs {
			if key.Window < window {
				flushed = append(flushed, stats)
				delete(shard.IPs, key)
			}
		}
		shard.Unlock()
	}
	return flushed
}
