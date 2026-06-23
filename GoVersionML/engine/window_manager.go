// window_manager.go manages time-windowed aggregation for Netflow records.
// It tracks the highest observed timestamp window and flushes completed
// windows based on the configured flush policy.
package engine

import (
	"sync/atomic"

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
