package engine

import (
	"sync/atomic"
	"time"

	"goversion/models"
)

type WindowFlushMode int

const (
	WindowFlushAssumeOrdered WindowFlushMode = iota
	WindowFlushStrictEOF
)

type WindowFlushPolicy struct {
	Mode WindowFlushMode
}

type NetflowWindowManager struct {
	aggregator    *Aggregator
	policy        WindowFlushPolicy
	currentWindow atomic.Int64
}

func NewNetflowWindowManager(policy WindowFlushPolicy) *NetflowWindowManager {
	return &NetflowWindowManager{
		aggregator: NewAggregator(),
		policy:     policy,
	}
}

func (wm *NetflowWindowManager) ProcessRecords(records []models.NetflowRecord) []*IPStats {
	var localMaxWindow int64
	for _, record := range records {
		wm.aggregator.Update(record)
		win := sniffTimestamp(record.First)
		if win > localMaxWindow {
			localMaxWindow = win
		}
	}

	if wm.policy.Mode == WindowFlushStrictEOF {
		return nil
	}

	if localMaxWindow > 0 {
		return wm.updateMaxWindowAndFlush(localMaxWindow)
	}
	return nil
}

func (wm *NetflowWindowManager) FlushFinal() []*IPStats {
	return wm.aggregator.FlushAll()
}

func (wm *NetflowWindowManager) updateMaxWindowAndFlush(win int64) []*IPStats {
	curr := wm.currentWindow.Load()
	for win > curr {
		if wm.currentWindow.CompareAndSwap(curr, win) {
			break
		}
		curr = wm.currentWindow.Load()
	}

	if win > curr {
		return wm.aggregator.ExtractAndFlushBefore(win - 300)
	}
	return nil
}

type PcapWindowManager struct {
	pcapAggregator *PcapAggregator
	policy         WindowFlushPolicy
	currentWindow  atomic.Int64
}

func NewPcapWindowManager(policy WindowFlushPolicy) *PcapWindowManager {
	return &PcapWindowManager{
		pcapAggregator: NewPcapAggregator(),
		policy:         policy,
	}
}

func (wm *PcapWindowManager) ProcessRecords(records []models.PcapRecord) []*PcapIPStats {
	var localMaxWindow int64
	for _, record := range records {
		wm.pcapAggregator.Update(record)
		win := int64(record.Timestamp) / 300 * 300
		if win > localMaxWindow {
			localMaxWindow = win
		}
	}

	if wm.policy.Mode == WindowFlushStrictEOF {
		return nil
	}

	if localMaxWindow > 0 {
		return wm.updateMaxWindowAndFlush(localMaxWindow)
	}
	return nil
}

func (wm *PcapWindowManager) FlushFinal() []*PcapIPStats {
	return wm.pcapAggregator.FlushAll()
}

func (wm *PcapWindowManager) updateMaxWindowAndFlush(win int64) []*PcapIPStats {
	curr := wm.currentWindow.Load()
	for win > curr {
		if wm.currentWindow.CompareAndSwap(curr, win) {
			break
		}
		curr = wm.currentWindow.Load()
	}

	if win > curr {
		return wm.pcapAggregator.ExtractAndFlushBefore(win - 300)
	}
	return nil
}

func sniffTimestamp(first string) int64 {
	if len(first) >= 23 && first[4] == '-' && first[10] == 'T' {
		year := int(first[0]-'0')*1000 + int(first[1]-'0')*100 + int(first[2]-'0')*10 + int(first[3]-'0')
		month := int(first[5]-'0')*10 + int(first[6]-'0')
		day := int(first[8]-'0')*10 + int(first[9]-'0')
		hour := int(first[11]-'0')*10 + int(first[12]-'0')
		minute := int(first[14]-'0')*10 + int(first[15]-'0')
		second := int(first[17]-'0')*10 + int(first[18]-'0')

		t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
		return t.Truncate(5 * time.Minute).Unix()
	}
	return 0
}
