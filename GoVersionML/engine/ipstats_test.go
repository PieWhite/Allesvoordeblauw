package engine

import (
	"math"
	"testing"
	"time"
)

// TestPortSymmetry targets the symmetry++ line.
func TestPortSymmetry(t *testing.T) {
	s := NewIPStats()
	s.AddOutboundDstPort(53)
	s.AddOutboundDstPort(80)

	s.AddInboundDstPort(53)
	s.AddInboundDstPort(443)

	symmetry := s.calculatePortSymmetry()

	if symmetry != 1 {
		t.Errorf("Expected symmetry 1, got %v", symmetry)
	}
}

// TestIAT_Math_Precision verifies the Python-style variance calculation.
func TestIAT_Math_Precision(t *testing.T) {
	s := NewIPStats()
	target := TargetKey{IP: "8.8.8.8", Port: 53}

	// Times: 10.0, 12.0.
	s.AddTargetStartTime(target, time.Unix(10, 0))
	s.AddTargetStartTime(target, time.Unix(12, 0))

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

func TestIPStats_HybridTransition(t *testing.T) {
	s := NewIPStats()
	
	// Add 30 unique Dst IPs to trigger map transition
	for i := 0; i < 30; i++ {
		s.AddUniqueDstIP(string([]byte{byte('A' + i)}))
	}
	// Verify that map is populated and count is 30
	if s.UniqueDstIPsMap == nil {
		t.Error("expected UniqueDstIPsMap to be initialized after 30 additions")
	}
	if s.NumUniqueDstIPs() != 30 {
		t.Errorf("expected 30 unique Dst IPs, got %d", s.NumUniqueDstIPs())
	}
	// Try adding duplicates and check count
	s.AddUniqueDstIP("A")
	s.AddUniqueDstIP("B")
	if s.NumUniqueDstIPs() != 30 {
		t.Errorf("expected count to remain 30 after duplicates, got %d", s.NumUniqueDstIPs())
	}

	// Add 30 unique Dst Ports
	for i := 0; i < 30; i++ {
		s.AddUniqueDstPort(i)
	}
	if s.UniqueDstPortsMap == nil {
		t.Error("expected UniqueDstPortsMap to be initialized")
	}
	if s.NumUniqueDstPorts() != 30 {
		t.Errorf("expected 30 unique Dst Ports, got %d", s.NumUniqueDstPorts())
	}
	s.AddUniqueDstPort(5)
	if s.NumUniqueDstPorts() != 30 {
		t.Errorf("expected count to remain 30, got %d", s.NumUniqueDstPorts())
	}

	// Add 30 unique Outbound ports
	for i := 0; i < 30; i++ {
		s.AddOutboundDstPort(i)
	}
	if s.OutboundDstPortsMap == nil {
		t.Error("expected OutboundDstPortsMap to be initialized")
	}
	if len(s.OutboundDstPorts) != 29 { // First goes to FirstOutboundPort
		t.Errorf("expected 29 elements in slice, got %d", len(s.OutboundDstPorts))
	}

	// Add 30 unique Inbound ports
	for i := 0; i < 30; i++ {
		s.AddInboundDstPort(i)
	}
	if s.InboundDstPortsMap == nil {
		t.Error("expected InboundDstPortsMap to be initialized")
	}
	
	// Test port symmetry using hybrid map
	sym := s.calculatePortSymmetry()
	if sym != 30 {
		t.Errorf("expected port symmetry 30, got %f", sym)
	}

	// Add 30 target start times
	for i := 0; i < 30; i++ {
		tk := TargetKey{IP: "1.1.1.1", Port: i}
		s.AddTargetStartTime(tk, time.Unix(int64(i), 0))
	}
	if s.TargetLastTimesMap == nil {
		t.Error("expected TargetLastTimesMap to be initialized")
	}
	if len(s.TargetLastTimes) != 29 { // First goes to FirstTarget
		t.Errorf("expected 29 in slice, got %d", len(s.TargetLastTimes))
	}
	// Add same target start time again to verify it updates existing count/times instead of inserting new
	tk := TargetKey{IP: "1.1.1.1", Port: 5}
	s.AddTargetStartTime(tk, time.Unix(100, 0))
	if len(s.TargetLastTimes) != 29 {
		t.Errorf("expected size to remain 29, got %d", len(s.TargetLastTimes))
	}
}

