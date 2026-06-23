package engine

import (
	"sync"

	"goversion/models"
)

type PcapShard struct {
	sync.RWMutex
	IPs map[WindowKey]*PcapIPStats
}

// PcapAggregator performs lock-free sequential aggregation of PcapRecord packets
// into statistical windows grouped by IP address.
// (Updated: Now uses 64 shards with RWMutex for safe concurrent aggregation across multiple workers).
type PcapAggregator struct {
	shards [numShards]*PcapShard
}

func NewPcapAggregator() *PcapAggregator {
	p := &PcapAggregator{}
	for i := 0; i < numShards; i++ {
		p.shards[i] = &PcapShard{
			IPs: make(map[WindowKey]*PcapIPStats),
		}
	}
	return p
}

func (p *PcapAggregator) getShardIndex(ip uint32) int {
	h := ip * 2654435761 // Knuth's multiplicative hash
	return int(h >> 26)  // top 6 bits → [0, 63]
}

// Update routes packet records to their respective IP stats blocks safely
func (p *PcapAggregator) Update(record models.PcapRecord) {
	// Group into 5-minute (300-second) windows
	win := int64(record.Timestamp) / 300 * 300

	if record.SrcIP != "" {
		if srcIP, ok := ParseIPv4(record.SrcIP); ok {
			keySrc := WindowKey{IP: srcIP, Window: win}
			shardIdx := p.getShardIndex(srcIP)
			shard := p.shards[shardIdx]

			shard.Lock()
			stats, exists := shard.IPs[keySrc]
			if !exists {
				stats = NewPcapIPStats(srcIP, win)
				shard.IPs[keySrc] = stats
			}
			stats.Update(record, true) // Outbound
			shard.Unlock()
		}
	}

	if record.DstIP != "" {
		if dstIP, ok := ParseIPv4(record.DstIP); ok {
			keyDst := WindowKey{IP: dstIP, Window: win}
			shardIdx := p.getShardIndex(dstIP)
			shard := p.shards[shardIdx]

			shard.Lock()
			statsDst, existsDst := shard.IPs[keyDst]
			if !existsDst {
				statsDst = NewPcapIPStats(dstIP, win)
				shard.IPs[keyDst] = statsDst
			}
			statsDst.Update(record, false) // Inbound
			shard.Unlock()
		}
	}
}

// ExtractAndFlushBefore extracts and clears stats older than the specified threshold
func (p *PcapAggregator) ExtractAndFlushBefore(window int64) []*PcapIPStats {
	var flushed []*PcapIPStats
	for i := 0; i < numShards; i++ {
		shard := p.shards[i]
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

// FlushAll extracts and clears all currently stored stats
func (p *PcapAggregator) FlushAll() []*PcapIPStats {
	var flushed []*PcapIPStats
	for i := 0; i < numShards; i++ {
		shard := p.shards[i]
		shard.Lock()
		for key, stats := range shard.IPs {
			flushed = append(flushed, stats)
			delete(shard.IPs, key)
		}
		shard.Unlock()
	}
	return flushed
}

func (p *PcapAggregator) NumActiveKeys() int {
	var count int
	for i := 0; i < numShards; i++ {
		shard := p.shards[i]
		shard.RLock()
		count += len(shard.IPs)
		shard.RUnlock()
	}
	return count
}
