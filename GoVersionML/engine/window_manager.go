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

var monthDays = [12]int64{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}

// fastUnixTime returns the Unix timestamp (in seconds) for a given UTC date.
func fastUnixTime(year, month, day, hour, minute, second int) int64 {
	y := int64(year)
	m := int64(month)
	d := int64(day)
	
	// Number of leap years between 1970 and year-1
	prevYear := y - 1
	leapDays := prevYear/4 - prevYear/100 + prevYear/400 - 477
	
	// Days in previous years since 1970
	days := (y-1970)*365 + leapDays
	
	// Days in current year before this month
	days += monthDays[m-1]
	
	// If this is a leap year and we are past February, add 1 day
	if m > 2 && ((year%4 == 0 && year%100 != 0) || (year%400 == 0)) {
		days++
	}
	
	// Add days in current month
	days += d - 1
	
	return days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second)
}

func sniffTimestamp(first string) int64 {
	if len(first) >= 23 && first[4] == '-' && first[10] == 'T' {
		year := int(first[0]-'0')*1000 + int(first[1]-'0')*100 + int(first[2]-'0')*10 + int(first[3]-'0')
		month := int(first[5]-'0')*10 + int(first[6]-'0')
		day := int(first[8]-'0')*10 + int(first[9]-'0')
		hour := int(first[11]-'0')*10 + int(first[12]-'0')
		minute := int(first[14]-'0')*10 + int(first[15]-'0')
		second := int(first[17]-'0')*10 + int(first[18]-'0')

		sec := fastUnixTime(year, month, day, hour, minute, second)
		return (sec / 300) * 300
	}

	if len(first) >= 19 && first[4] == '-' && first[10] == ' ' {
		year := int(first[0]-'0')*1000 + int(first[1]-'0')*100 + int(first[2]-'0')*10 + int(first[3]-'0')
		month := int(first[5]-'0')*10 + int(first[6]-'0')
		day := int(first[8]-'0')*10 + int(first[9]-'0')
		hour := int(first[11]-'0')*10 + int(first[12]-'0')
		minute := int(first[14]-'0')*10 + int(first[15]-'0')
		second := int(first[17]-'0')*10 + int(first[18]-'0')

		sec := fastUnixTime(year, month, day, hour, minute, second)
		return (sec / 300) * 300
	}
	return 0
}

