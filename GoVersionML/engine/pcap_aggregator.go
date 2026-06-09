package engine

import (
	"goversion/models"
)

type PcapAggregator struct {
	IPs map[WindowKey]*PcapIPStats
}

func NewPcapAggregator() *PcapAggregator {
	return &PcapAggregator{
		IPs: make(map[WindowKey]*PcapIPStats),
	}
}

func (p *PcapAggregator) Update(record models.PcapRecord) {
	win := int64(record.Timestamp) / 300 * 300

	if record.SrcIP != "" {
		keySrc := WindowKey{IP: record.SrcIP, Window: win}
		stats, exists := p.IPs[keySrc]
		if !exists {
			stats = NewPcapIPStats(record.SrcIP, win)
			p.IPs[keySrc] = stats
		}
		stats.Update(record, true)
	}

	if record.DstIP != "" {
		keyDst := WindowKey{IP: record.DstIP, Window: win}
		statsDst, existsDst := p.IPs[keyDst]
		if !existsDst {
			statsDst = NewPcapIPStats(record.DstIP, win)
			p.IPs[keyDst] = statsDst
		}
		statsDst.Update(record, false)
	}
}

func (p *PcapAggregator) FlushWindow(window int64) []*PcapIPStats {
	var flushed []*PcapIPStats
	for key, stats := range p.IPs {
		if key.Window < window {
			flushed = append(flushed, stats)
			delete(p.IPs, key)
		}
	}
	return flushed
}

func (p *PcapAggregator) FlushAll() []*PcapIPStats {
	var flushed []*PcapIPStats
	for key, stats := range p.IPs {
		flushed = append(flushed, stats)
		delete(p.IPs, key)
	}
	return flushed
}
