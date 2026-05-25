package engine

import (
	"math"
	"testing"
)

// TestPortSymmetry targets the symmetry++ line.
func TestPortSymmetry(t *testing.T) {
	s := NewIPStats()
	s.OutboundDstPorts = []int{53, 80}
	s.InboundDstPorts = []int{53, 443}

	symmetry := s.calculatePortSymmetry()

	if symmetry != 1 {
		t.Errorf("Expected symmetry 1, got %v", symmetry)
	}
}

// TestIAT_Math_Precision verifies the Python-style variance calculation.
func TestIAT_Math_Precision(t *testing.T) {
	s := NewIPStats()
	s.Window = 0
	s.UniqueDstIPs = []string{"8.8.8.8"}
	s.TargetStartTimes = []CompactTime{
		{IPIdx: 0, Port: 53, Offset: 10.0},
		{IPIdx: 0, Port: 53, Offset: 12.0},
	}

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

func TestToMLVector_EmptyFlow(t *testing.T) {
	s := NewIPStats()
	s.FlowCount = 0

	vec := s.ToMLVector()
	if len(vec) != 21 {
		t.Errorf("Expected length 21, got %d", len(vec))
	}
	for i, v := range vec {
		if v != 0 {
			t.Errorf("Expected 0 at index %d, got %v", i, v)
		}
	}
}
