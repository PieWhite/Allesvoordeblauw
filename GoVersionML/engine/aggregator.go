package engine

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goversion/models"
)

const numShards = 64

type WindowKey struct {
	IP     uint32
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

func (a *Aggregator) getShardIndex(ip uint32) int {
	// FNV-1a inspired hash for uint32 — fast and well-distributed
	h := ip * 2654435761 // Knuth's multiplicative hash
	return int(h >> 26)  // top 6 bits → [0, 63]
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

	if len(s) >= 19 && s[4] == '-' && s[10] == ' ' {
		year := int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
		month := int(s[5]-'0')*10 + int(s[6]-'0')
		day := int(s[8]-'0')*10 + int(s[9]-'0')
		hour := int(s[11]-'0')*10 + int(s[12]-'0')
		minute := int(s[14]-'0')*10 + int(s[15]-'0')
		second := int(s[17]-'0')*10 + int(s[18]-'0')
		msec := 0
		if len(s) >= 23 && s[19] == '.' {
			msec = int(s[20]-'0')*100 + int(s[21]-'0')*10 + int(s[22]-'0')
		}
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

func getWindowKey(ip uint32, t time.Time) WindowKey {
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
		srcIP, srcOk := ParseIPv4(record.Src4Addr)
		if srcOk {
			key := getWindowKey(srcIP, first)
			shardIdx := a.getShardIndex(srcIP)
			shard := a.shards[shardIdx]

			dstIP, _ := ParseIPv4(record.Dst4Addr)

			shard.Lock()
			stats, exists := shard.IPs[key]
			if !exists {
				stats = NewIPStats()
				stats.IP = srcIP
				shard.IPs[key] = stats
			}

			a.updateOutboundStats(stats, record, first, dstIP)
			shard.Unlock()
		}
	}

	if record.Dst4Addr != "" {
		dstIP, dstOk := ParseIPv4(record.Dst4Addr)
		if dstOk {
			key := getWindowKey(dstIP, first)
			shardIdx := a.getShardIndex(dstIP)
			shard := a.shards[shardIdx]

			shard.Lock()
			stats, exists := shard.IPs[key]
			if !exists {
				stats = NewIPStats()
				stats.IP = dstIP
				shard.IPs[key] = stats
			}
			updateInboundStats(stats, record)
			shard.Unlock()
		}
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

func (a *Aggregator) updateOutboundStats(stats *IPStats, record models.NetflowRecord, first time.Time, dstIP uint32) {
	stats.FlowCount++

	stats.AddUniqueDstIP(dstIP)
	stats.AddUniqueDstPort(record.DstPort)
	stats.AddOutboundDstPort(record.DstPort)

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

	a.updateTimingMetrics(stats, record, first, dstIP)
}

func updateInboundStats(stats *IPStats, record models.NetflowRecord) {
	stats.AddInboundDstPort(record.DstPort)
}

func (a *Aggregator) updateTimingMetrics(s *IPStats, record models.NetflowRecord, first time.Time, dstIP uint32) {
	tKey := TargetKey{IP: dstIP, Port: record.DstPort}
	s.AddTargetStartTime(tKey, first)

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
		shard.Unlock()
	}
	return flushed
}

func (a *Aggregator) NumActiveKeys() int {
	var count int
	for i := 0; i < numShards; i++ {
		shard := a.shards[i]
		shard.RLock()
		count += len(shard.IPs)
		shard.RUnlock()
	}
	return count
}

func (a *Aggregator) Merge(other *Aggregator) {
	for i := 0; i < numShards; i++ {
		shard := a.shards[i]
		otherShard := other.shards[i]

		otherShard.Lock()
		for key, otherStats := range otherShard.IPs {
			shard.Lock()
			stats, exists := shard.IPs[key]
			if !exists {
				shard.IPs[key] = otherStats
			} else {
				stats.Merge(otherStats)
			}
			shard.Unlock()
		}
		otherShard.Unlock()
	}
}

