// aggregator_test.go verifies sharded aggregation correctness including
// timestamp parsing, protocol/flag tracking, window flushing, and thread safety.
package engine

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"goversion/models"
)

func parseTimeHelper(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000", s)
	return t
}

func getStatsForIP(a *Aggregator, ip string) *IPStats {
	targetIP, ok := ParseIPv4(ip)
	if !ok {
		return nil
	}
	for _, s := range a.AllIPStats() {
		if s.IP == targetIP {
			return s
		}
	}
	return nil
}

func TestParseTimestamp_Boundary(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantOk bool
	}{
		{"Standard", "2026-03-17T11:08:24.123", true},
		{"Leap Day", "2024-02-29T23:59:59.999", true},
		{"Incorrect Separator", "2026/03/17 11:08:24", false},
		{"Empty", "", false},
		{"Truncated", "2026-03-17", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAggregator()
			_, ok := a.parseTimestamp(tt.input)
			if ok != tt.wantOk {
				t.Errorf("%s: got %v, want %v", tt.name, ok, tt.wantOk)
			}
		})
	}
}

func TestAggregator_Update_DataIntegrity(t *testing.T) {
	a := NewAggregator()
	rec := models.NetflowRecord{
		Src4Addr:  "10.0.0.1",
		Dst4Addr:  "192.168.1.1",
		DstPort:   443,
		Proto:     6,
		InBytes:   1000,
		InPackets: 10,
		First:     "2026-03-17T10:00:00.000",
		Last:      "2026-03-17T10:00:01.000",
	}

	a.Update(rec)

	allStats := a.AllIPStats()
	if len(allStats) != 2 {
		t.Errorf("expected 2 IP stats entries, got %d", len(allStats))
	}

	srcStats := getStatsForIP(a, "10.0.0.1")
	if srcStats == nil {
		t.Fatal("Source IP stats not found in aggregator")
	}

	if srcStats.TotalBytes != 1000 || srcStats.FlowCount != 1 {
		t.Errorf("Source stats mismatch: bytes=%v, flows=%v", srcStats.TotalBytes, srcStats.FlowCount)
	}

	dstStats := getStatsForIP(a, "192.168.1.1")
	found := dstStats.FirstInboundPort == 443
	if !found {
		for _, port := range dstStats.InboundDstPorts {
			if port == 443 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Destination inbound port 443 was not tracked")
	}
}

func TestUpdate_ProtocolsAndFlags(t *testing.T) {
	a := NewAggregator()

	records := []models.NetflowRecord{
		{Src4Addr: "1.1.1.1", Proto: 17, First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"},
		{Src4Addr: "1.1.1.1", Proto: 1, First: "2026-03-17T12:00:01.000", Last: "2026-03-17T12:00:01.000"},
		{Src4Addr: "1.1.1.1", Proto: 6, TCPFlags: "R", First: "2026-03-17T12:00:02.000", Last: "2026-03-17T12:00:02.000"},
	}

	for _, r := range records {
		a.Update(r)
	}

	stats := getStatsForIP(a, "1.1.1.1")

	if stats.UDPCount != 1 {
		t.Errorf("Expected UDPCount 1, got %v", stats.UDPCount)
	}
	if stats.ICMPCount != 1 {
		t.Errorf("Expected ICMPCount 1, got %v", stats.ICMPCount)
	}
	if stats.RstCount != 1 {
		t.Errorf("Expected RstCount 1, got %v", stats.RstCount)
	}
}

func TestUpdate_DurationClamping(t *testing.T) {
	a := NewAggregator()
	rec := models.NetflowRecord{
		Src4Addr: "1.1.1.1",
		First:    "2026-03-17T12:00:05.000",
		Last:     "2026-03-17T12:00:00.000",
	}

	a.Update(rec)
	stats := getStatsForIP(a, "1.1.1.1")

	if stats.SumDurationSec != 0 {
		t.Errorf("Expected clamped duration 0, got %v", stats.SumDurationSec)
	}
}

func TestAggregator_Concurrency(t *testing.T) {
	a := NewAggregator()
	var wg sync.WaitGroup
	numWorkers := 100
	recordsPerWorker := 1000

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < recordsPerWorker; j++ {
				a.Update(models.NetflowRecord{
					Src4Addr: "10.0.0.1",
					First:    "2026-03-17T12:00:00.000",
					Last:     "2026-03-17T12:00:00.000",
					InBytes:  10,
				})
				a.Update(models.NetflowRecord{
					Src4Addr: fmt.Sprintf("10.1.0.%d", w),
					First:    "2026-03-17T12:00:00.000",
					Last:     "2026-03-17T12:00:00.000",
					InBytes:  20,
				})
			}
		}(i)
	}
	wg.Wait()

	stats := getStatsForIP(a, "10.0.0.1")
	if stats == nil {
		t.Fatal("Expected stats for 10.0.0.1")
	}

	expectedFlows := numWorkers * recordsPerWorker
	expectedBytes := float64(expectedFlows * 10)

	if stats.FlowCount != expectedFlows {
		t.Errorf("Expected %d flows, got %d", expectedFlows, stats.FlowCount)
	}
	if stats.TotalBytes != expectedBytes {
		t.Errorf("Expected %v bytes, got %v", expectedBytes, stats.TotalBytes)
	}
}

func TestAggregator_ExtractAndFlushBefore(t *testing.T) {
	a := NewAggregator()
	a.Update(models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"})
	a.Update(models.NetflowRecord{Src4Addr: "2.2.2.2", First: "2026-03-17T12:05:00.000", Last: "2026-03-17T12:05:00.000"})

	flushed := a.ExtractAndFlushBefore(1773749100)

	if len(flushed) != 1 {
		t.Fatalf("Expected 1 flushed stats, got %d", len(flushed))
	}
	if FormatIPv4(flushed[0].IP) != "1.1.1.1" {
		t.Errorf("Expected IP 1.1.1.1 flushed, got %s", FormatIPv4(flushed[0].IP))
	}

	remaining := a.AllIPStats()
	if len(remaining) != 1 {
		t.Fatalf("Expected 1 remaining stats, got %d", len(remaining))
	}
	if FormatIPv4(remaining[0].IP) != "2.2.2.2" {
		t.Errorf("Expected IP 2.2.2.2 remaining, got %s", FormatIPv4(remaining[0].IP))
	}
}

func TestAggregator_Update_TCPFlagsAndPorts(t *testing.T) {
	a := NewAggregator()

	a.Update(models.NetflowRecord{
		Src4Addr: "3.3.3.3",
		Proto:    6,
		TCPFlags: "S",
		DstPort:  80,
		First:    "2026-03-17T12:00:00.000",
		Last:     "2026-03-17T12:00:00.000",
	})

	stats := getStatsForIP(a, "3.3.3.3")

	if stats.SynOnlyCount != 1 {
		t.Errorf("Expected SynOnlyCount=1, got %v", stats.SynOnlyCount)
	}
	if stats.WellKnownPortCount != 1 {
		t.Errorf("Expected WellKnownPortCount=1, got %v", stats.WellKnownPortCount)
	}

	vec := stats.ToMLVector()
	if vec[18] != 100.0 {
		t.Errorf("Expected 100%% pct_syn_only, got %v", vec[18])
	}
}
