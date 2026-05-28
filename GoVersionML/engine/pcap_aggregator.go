package engine

import (
	"goversion/models"
)

// PcapAggregator performs lock-free sequential aggregation of PcapRecord packets 
// into statistical windows grouped by IP address.
type PcapAggregator struct {
	IPs map[WindowKey]*PcapIPStats
}

func NewPcapAggregator() *PcapAggregator {
	return &PcapAggregator{
		IPs: make(map[WindowKey]*PcapIPStats),
	}
}

// Update routes packet records to their respective IP stats blocks lock-freely
func (p *PcapAggregator) Update(record models.PcapRecord) {
	// Group into 5-minute (300-second) windows
	win := int64(record.Timestamp) / 300 * 300

	if record.SrcIP != "" {
		keySrc := WindowKey{IP: record.SrcIP, Window: win}
		stats, exists := p.IPs[keySrc]
		if !exists {
			stats = NewPcapIPStats(record.SrcIP, win)
			p.IPs[keySrc] = stats
		}
		stats.Update(record, true) // Outbound
	}

	if record.DstIP != "" {
		keyDst := WindowKey{IP: record.DstIP, Window: win}
		statsDst, existsDst := p.IPs[keyDst]
		if !existsDst {
			statsDst = NewPcapIPStats(record.DstIP, win)
			p.IPs[keyDst] = statsDst
		}
		statsDst.Update(record, false) // Inbound
	}
}

// ExtractAndFlushBefore extracts and clears stats older than the specified threshold
func (p *PcapAggregator) ExtractAndFlushBefore(window int64) []*PcapIPStats {
	var flushed []*PcapIPStats
	for key, stats := range p.IPs {
		if key.Window < window {
			flushed = append(flushed, stats)
			delete(p.IPs, key)
		}
	}
	return flushed
}

// FlushAll extracts and clears all currently stored stats
func (p *PcapAggregator) FlushAll() []*PcapIPStats {
	var flushed []*PcapIPStats
	for key, stats := range p.IPs {
		flushed = append(flushed, stats)
		delete(p.IPs, key)
	}
	return flushed
}
