package engine

import (
	"hash/fnv"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goversion/models"
)

const numShards = 64

type WindowKey struct {
	IP     string
	Window int64
}

type Shard struct {
	sync.RWMutex
	IPs map[WindowKey]*IPStats
	ips map[string]string // IP intern cache
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
			ips: make(map[string]string),
		}
	}
	return a
}

func (s *Shard) intern(ip string) string {
	if cached, exists := s.ips[ip]; exists {
		return cached
	}
	// Bounded size check to prevent memory leaks in long-running production pipelines.
	// If the cache grows too large, we reset it. Active strings in shard.IPs will remain
	// safely allocated and alive, while unused IPs will be naturally garbage-collected.
	if len(s.ips) > 50000 {
		s.ips = make(map[string]string)
	}
	safeIP := strings.Clone(ip)
	s.ips[safeIP] = safeIP
	return safeIP
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
	if err == nil {
		return t, true
	}

	t, err = time.Parse("2006-01-02 15:04:05", s)
	if err == nil {
		return t, true
	}

	t, err = time.Parse("2006-01-02 15:04:05.000", s)
	if err == nil {
		return t, true
	}

	if a.timestampWarningLogged.CompareAndSwap(false, true) {
		log.Printf("WARNING: failed to parse timestamp %q: %v (further warnings suppressed)", s, err)
	}
	return t, false
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
		internedSrc := shard.intern(record.Src4Addr)
		key.IP = internedSrc

		stats, exists := shard.IPs[key]
		if !exists {
			stats = NewIPStats()
			stats.IP = internedSrc
			shard.IPs[key] = stats
		}

		internedDst := shard.intern(record.Dst4Addr)
		a.updateOutboundStats(stats, record, first, internedDst)
		shard.Unlock()
	}

	if record.Dst4Addr != "" {
		key := getWindowKey(record.Dst4Addr, first)
		shardIdx := a.getShardIndex(key)
		shard := a.shards[shardIdx]

		shard.Lock()
		internedDst := shard.intern(record.Dst4Addr)
		key.IP = internedDst

		stats, exists := shard.IPs[key]
		if !exists {
			stats = NewIPStats()
			stats.IP = internedDst
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

func (a *Aggregator) updateOutboundStats(stats *IPStats, record models.NetflowRecord, first time.Time, internedDst string) {
	stats.FlowCount++

	if stats.UniqueDstIPs == nil {
		stats.UniqueDstIPs = make(map[string]struct{})
	}
	stats.UniqueDstIPs[internedDst] = struct{}{}

	if stats.UniqueDstPorts == nil {
		stats.UniqueDstPorts = make(map[int]struct{})
	}
	stats.UniqueDstPorts[record.DstPort] = struct{}{}

	if stats.OutboundDstPorts == nil {
		stats.OutboundDstPorts = make(map[int]struct{})
	}
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

	a.updateTimingMetrics(stats, record, first, internedDst)
}

func updateInboundStats(stats *IPStats, record models.NetflowRecord) {
	if stats.InboundDstPorts == nil {
		stats.InboundDstPorts = make(map[int]struct{})
	}
	stats.InboundDstPorts[record.DstPort] = struct{}{}
}

func (a *Aggregator) updateTimingMetrics(s *IPStats, record models.NetflowRecord, first time.Time, internedDst string) {
	tKey := TargetKey{IP: internedDst, Port: record.DstPort}
	if s.TargetStartTimes == nil {
		s.TargetStartTimes = make(map[TargetKey][]float64)
	}

	// This bounds the memory footprint and CPU sorting overhead, at the cost of approximating
	// the Inter-Arrival Time (IAT) metrics for very high-volume targets.
	if len(s.TargetStartTimes[tKey]) < 10 {
		s.TargetStartTimes[tKey] = append(s.TargetStartTimes[tKey], float64(first.UnixNano())/1e9)
	}

	if last, ok := a.parseTimestamp(record.Last); ok {
		duration := last.Sub(first).Seconds()
		if duration < 0 {
			duration = 0
		}
		s.SumDurationSec += duration
	}
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

// FlushAll removes and returns all IPStats currently in the aggregator, leaving it completely empty.
func (a *Aggregator) FlushAll() []*IPStats {
	var flushed []*IPStats
	for i := 0; i < numShards; i++ {
		shard := a.shards[i]
		shard.Lock()
		for key, stats := range shard.IPs {
			flushed = append(flushed, stats)
			delete(shard.IPs, key)
		}
		shard.ips = make(map[string]string) // clear intern cache as well
		shard.Unlock()
	}
	return flushed
}
