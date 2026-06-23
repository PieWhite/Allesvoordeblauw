// ipstats_test.go verifies the hybrid slice/map unique tracking data structures
// and their transition behavior at the 16-element threshold.
package engine

import (
	"testing"
	"time"
)

func TestIPStats_HybridTransition(t *testing.T) {
	s := NewIPStats()

	for i := 0; i < 30; i++ {
		s.AddUniqueDstIP(uint32(i + 1))
	}
	if s.UniqueDstIPsMap == nil {
		t.Error("expected UniqueDstIPsMap to be initialized after 30 additions")
	}
	if s.NumUniqueDstIPs() != 30 {
		t.Errorf("expected 30 unique Dst IPs, got %d", s.NumUniqueDstIPs())
	}
	s.AddUniqueDstIP(1)
	s.AddUniqueDstIP(2)
	if s.NumUniqueDstIPs() != 30 {
		t.Errorf("expected count to remain 30 after duplicates, got %d", s.NumUniqueDstIPs())
	}

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

	for i := 0; i < 30; i++ {
		s.AddInboundDstPort(i)
	}
	if s.InboundDstPortsMap == nil {
		t.Error("expected InboundDstPortsMap to be initialized")
	}

	sym := s.calculatePortSymmetry()
	if sym != 30 {
		t.Errorf("expected port symmetry 30, got %f", sym)
	}

	ipTest, _ := ParseIPv4("1.1.1.1")
	for i := 0; i < 30; i++ {
		tk := TargetKey{IP: ipTest, Port: i}
		s.AddTargetStartTime(tk, time.Unix(int64(i), 0))
	}
	if s.TargetLastTimesMap == nil {
		t.Error("expected TargetLastTimesMap to be initialized")
	}
	if len(s.TargetLastTimes) != 29 {
		t.Errorf("expected 29 in slice, got %d", len(s.TargetLastTimes))
	}
	tk := TargetKey{IP: ipTest, Port: 5}
	s.AddTargetStartTime(tk, time.Unix(100, 0))
	if len(s.TargetLastTimes) != 29 {
		t.Errorf("expected size to remain 29, got %d", len(s.TargetLastTimes))
	}
}
