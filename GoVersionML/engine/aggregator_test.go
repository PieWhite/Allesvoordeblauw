package engine

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"goversion/models"
)

// Helper to avoid repetitive error handling in tests
func parseTimeHelper(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000", s)
	return t
}

func getStatsForIP(a *Aggregator, ip string) *IPStats {
	for _, s := range a.AllIPStats() {
		if s.IP == ip {
			return s
		}
	}
	return nil
}

// TestParseTimestamp_Boundary checks the ISO-like format and internal state.
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
			a := NewAggregator() // New aggregator per test ensures clean log flag
			_, ok := a.parseTimestamp(tt.input)
			if ok != tt.wantOk {
				t.Errorf("%s: got %v, want %v", tt.name, ok, tt.wantOk)
			}
		})
	}
}

// TestAggregator_Update_DataIntegrity ensures Src and Dst stats are isolated.
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
	if dstStats == nil {
		t.Fatal("Destination IP stats not found in aggregator")
	}
	if _, ok := dstStats.InboundDstPorts[443]; !ok {
		t.Error("Destination inbound port 443 was not tracked")
	}
}

// TestUpdate_ProtocolsAndFlags targets UDP, ICMP, and RST count logic.
func TestUpdate_ProtocolsAndFlags(t *testing.T) {
	a := NewAggregator()

	records := []models.NetflowRecord{
		{Src4Addr: "1.1.1.1", Proto: 17, First: "2026-03-17T12:00:00.000"},               // UDP
		{Src4Addr: "1.1.1.1", Proto: 1, First: "2026-03-17T12:00:01.000"},                // ICMP
		{Src4Addr: "1.1.1.1", Proto: 6, TCPFlags: "R", First: "2026-03-17T12:00:02.000"}, // RST
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

// TestUpdate_DurationClamping targets: if duration < 0 { duration = 0 }
func TestUpdate_DurationClamping(t *testing.T) {
	a := NewAggregator()
	rec := models.NetflowRecord{
		Src4Addr: "1.1.1.1",
		First:    "2026-03-17T12:00:05.000",
		Last:     "2026-03-17T12:00:00.000", // Negative duration
	}

	a.Update(rec)
	stats := getStatsForIP(a, "1.1.1.1")

	if stats.SumDurationSec != 0 {
		t.Errorf("Expected clamped duration 0, got %v", stats.SumDurationSec)
	}
}

// TestPortSymmetry targets the symmetry++ line.
func TestPortSymmetry(t *testing.T) {
	a := NewAggregator()
	ts := "2026-03-17T12:00:00.000"

	// Outbound from 10.0.0.1 perspective
	a.Update(models.NetflowRecord{
		Src4Addr: "10.0.0.1",
		Dst4Addr: "8.8.8.8",
		DstPort:  53,
		First:    ts,
	})
	// Inbound to 10.0.0.1 perspective (it is the Dst4Addr)
	a.Update(models.NetflowRecord{
		Src4Addr: "8.8.8.8",
		Dst4Addr: "10.0.0.1",
		DstPort:  53,
		First:    ts,
	})

	stats := getStatsForIP(a, "10.0.0.1")
	symmetry := stats.calculatePortSymmetry()

	if symmetry != 1 {
		t.Errorf("Expected symmetry 1, got %v", symmetry)
	}
}

// TestIAT_Math_Precision verifies the Python-style variance calculation.
func TestIAT_Math_Precision(t *testing.T) {
	s := NewIPStats()
	target := TargetKey{IP: "8.8.8.8", Port: 53}

	// Times: 10.0, 12.0.
	// Diffs: [0, 2.0]
	s.TargetStartTimes[target] = []float64{10.0, 12.0}

	mean, variance, cv := s.calculateIATMetrics()

	if mean != 1.0 {
		t.Errorf("expected mean 1.0, got %v", mean)
	}
	if variance != 2.0 {
		t.Errorf("expected variance 2.0, got %v", variance)
	}
	if math.Abs(cv-1.41421356) > 1e-7 {
		t.Errorf("expected CV ~1.4142, got %v", cv)
	}
}

// TestToMLVector_Sanitization checks for division-by-zero protection.
func TestToMLVector_Sanitization(t *testing.T) {
	s := NewIPStats()
	s.FlowCount = 5

	vec := s.ToMLVector()

	for i, val := range vec {
		if math.IsNaN(val) || math.IsInf(val, 0) {
			t.Errorf("Index %d is non-finite: %v", i, val)
		}
	}

	if vec[31] != 0 {
		t.Errorf("Feature 31 (ip_port_ratio) expected 0, got %v", vec[31])
	}
}

// TestAggregator_Concurrency hammers the aggregator from many goroutines to ensure thread safety
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
				// High contention target (all workers write here)
				a.Update(models.NetflowRecord{
					Src4Addr: "10.0.0.1",
					First:    "2026-03-17T12:00:00.000",
					InBytes:  10,
				})
				// Low contention target (one worker writes here)
				a.Update(models.NetflowRecord{
					Src4Addr: fmt.Sprintf("10.1.0.%d", w),
					First:    "2026-03-17T12:00:00.000",
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
