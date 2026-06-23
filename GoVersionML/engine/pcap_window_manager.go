// pcap_window_manager.go manages time-windowed aggregation for PCAP packet
// records, flushing completed windows based on the configured flush policy.
package engine

import (
	"sync/atomic"

	"goversion/models"
)

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
