package engine

import (
	"math"
	"testing"
	"time"

	"goversion/models"
)

// Helper to avoid repetitive error handling in tests
func parseTimeHelper(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000", s)
	return t
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

	if len(a.IPs) != 2 {
		t.Errorf("expected 2 IP stats entries, got %d", len(a.IPs))
	}

	expectedTime := time.Date(2026, 3, 17, 10, 0, 0, 0, time.UTC)
	srcKey := getTimeWindowKey("10.0.0.1", expectedTime)

	srcStats, exists := a.IPs[srcKey]
	if !exists {
		t.Fatal("Source IP stats not found in aggregator")
	}

	if srcStats.TotalBytes != 1000 || srcStats.FlowCount != 1 {
		t.Errorf("Source stats mismatch: bytes=%v, flows=%v", srcStats.TotalBytes, srcStats.FlowCount)
	}

	dstKey := getTimeWindowKey("192.168.1.1", expectedTime)
	dstStats := a.IPs[dstKey]
	if !dstStats.InboundDstPorts[443] {
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

	stats := a.getIPStats("1.1.1.1", parseTimeHelper("2026-03-17T12:00:00.000"))

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
	stats := a.getIPStats("1.1.1.1", parseTimeHelper(rec.First))

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

	stats := a.getIPStats("10.0.0.1", parseTimeHelper(ts))
	symmetry := stats.calculatePortSymmetry()

	if symmetry != 1 {
		t.Errorf("Expected symmetry 1, got %v", symmetry)
	}
}

// TestIAT_Math_Precision verifies the Python-style variance calculation.
func TestIAT_Math_Precision(t *testing.T) {
	s := NewIPStats()
	target := "8.8.8.8:53"

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

	if vec[16] != 0 {
		t.Errorf("Feature 16 (ip_port_ratio) expected 0, got %v", vec[16])
	}
}
