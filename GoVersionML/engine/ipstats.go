// ipstats.go defines per-IP traffic statistics accumulated within a time
// window. It uses a hybrid slice/map strategy for unique value tracking:
// small cardinalities use linear scans on slices, promoting to maps at a
// threshold of 16 elements for O(1) lookups.
package engine

import (
	"sync"
	"time"
)

type TargetKey struct {
	IP   uint32
	Port int
}

type TargetLastTime struct {
	Target       TargetKey
	LastSeenTime float64
}

type IPStats struct {
	IP        uint32
	FlowCount int

	HasFirstDstIP   bool
	FirstDstIP      uint32
	UniqueDstIPs    []uint32
	UniqueDstIPsMap map[uint32]struct{}

	HasFirstDstPort   bool
	FirstDstPort      int
	UniqueDstPorts    []int
	UniqueDstPortsMap map[int]struct{}

	HasFirstInbound    bool
	FirstInboundPort   int
	InboundDstPorts    []int
	InboundDstPortsMap map[int]struct{}

	TotalBytes         float64
	TotalPackets       float64
	TCPCount           float64
	UDPCount           float64
	ICMPCount          float64
	SynOnlyCount       float64
	RstCount           float64
	WellKnownPortCount float64
	SumDurationSec     float64

	IatCount float64
	IatMean  float64
	IatM2    float64

	HasFirstTarget      bool
	FirstTarget         TargetKey
	FirstTargetLastTime float64
	TargetLastTimes     []TargetLastTime
	TargetLastTimesMap  map[TargetKey]int
}

var ipStatsPool = sync.Pool{
	New: func() interface{} {
		return &IPStats{}
	},
}

func NewIPStats() *IPStats {
	return ipStatsPool.Get().(*IPStats)
}

func RecycleIPStats(s *IPStats) {
	s.Reset()
	ipStatsPool.Put(s)
}

func (s *IPStats) Reset() {
	s.IP = 0
	s.FlowCount = 0

	s.HasFirstDstIP = false
	s.FirstDstIP = 0
	if cap(s.UniqueDstIPs) > 1024 {
		s.UniqueDstIPs = nil
	} else {
		s.UniqueDstIPs = s.UniqueDstIPs[:0]
	}
	s.UniqueDstIPsMap = nil

	s.HasFirstDstPort = false
	s.FirstDstPort = 0
	if cap(s.UniqueDstPorts) > 1024 {
		s.UniqueDstPorts = nil
	} else {
		s.UniqueDstPorts = s.UniqueDstPorts[:0]
	}
	s.UniqueDstPortsMap = nil

	s.HasFirstInbound = false
	s.FirstInboundPort = 0
	if cap(s.InboundDstPorts) > 1024 {
		s.InboundDstPorts = nil
	} else {
		s.InboundDstPorts = s.InboundDstPorts[:0]
	}
	s.InboundDstPortsMap = nil

	s.TotalBytes = 0
	s.TotalPackets = 0
	s.TCPCount = 0
	s.UDPCount = 0
	s.ICMPCount = 0
	s.SynOnlyCount = 0
	s.RstCount = 0
	s.WellKnownPortCount = 0
	s.SumDurationSec = 0

	s.IatCount = 0
	s.IatMean = 0
	s.IatM2 = 0

	s.HasFirstTarget = false
	s.FirstTarget = TargetKey{}
	s.FirstTargetLastTime = 0
	if cap(s.TargetLastTimes) > 1024 {
		s.TargetLastTimes = nil
	} else {
		s.TargetLastTimes = s.TargetLastTimes[:0]
	}
	s.TargetLastTimesMap = nil
}

func (s *IPStats) AddUniqueDstIP(val uint32) {
	if !s.HasFirstDstIP {
		s.FirstDstIP = val
		s.HasFirstDstIP = true
		return
	}
	if s.FirstDstIP == val {
		return
	}
	if s.UniqueDstIPsMap != nil {
		if _, exists := s.UniqueDstIPsMap[val]; exists {
			return
		}
		s.UniqueDstIPsMap[val] = struct{}{}
		s.UniqueDstIPs = append(s.UniqueDstIPs, val)
		return
	}
	for _, v := range s.UniqueDstIPs {
		if v == val {
			return
		}
	}
	if len(s.UniqueDstIPs) >= 16 {
		s.UniqueDstIPsMap = make(map[uint32]struct{})
		for _, v := range s.UniqueDstIPs {
			s.UniqueDstIPsMap[v] = struct{}{}
		}
		s.UniqueDstIPsMap[val] = struct{}{}
	}
	s.UniqueDstIPs = append(s.UniqueDstIPs, val)
}

func (s *IPStats) NumUniqueDstIPs() int {
	if !s.HasFirstDstIP {
		return 0
	}
	return 1 + len(s.UniqueDstIPs)
}

func (s *IPStats) AddUniqueDstPort(val int) {
	if !s.HasFirstDstPort {
		s.FirstDstPort = val
		s.HasFirstDstPort = true
		return
	}
	if s.FirstDstPort == val {
		return
	}
	if s.UniqueDstPortsMap != nil {
		if _, exists := s.UniqueDstPortsMap[val]; exists {
			return
		}
		s.UniqueDstPortsMap[val] = struct{}{}
		s.UniqueDstPorts = append(s.UniqueDstPorts, val)
		return
	}
	for _, v := range s.UniqueDstPorts {
		if v == val {
			return
		}
	}
	if len(s.UniqueDstPorts) >= 16 {
		s.UniqueDstPortsMap = make(map[int]struct{})
		for _, v := range s.UniqueDstPorts {
			s.UniqueDstPortsMap[v] = struct{}{}
		}
		s.UniqueDstPortsMap[val] = struct{}{}
	}
	s.UniqueDstPorts = append(s.UniqueDstPorts, val)
}

func (s *IPStats) NumUniqueDstPorts() int {
	if !s.HasFirstDstPort {
		return 0
	}
	return 1 + len(s.UniqueDstPorts)
}

func (s *IPStats) AddInboundDstPort(val int) {
	if !s.HasFirstInbound {
		s.FirstInboundPort = val
		s.HasFirstInbound = true
		return
	}
	if s.FirstInboundPort == val {
		return
	}
	if s.InboundDstPortsMap != nil {
		if _, exists := s.InboundDstPortsMap[val]; exists {
			return
		}
		s.InboundDstPortsMap[val] = struct{}{}
		s.InboundDstPorts = append(s.InboundDstPorts, val)
		return
	}
	for _, v := range s.InboundDstPorts {
		if v == val {
			return
		}
	}
	if len(s.InboundDstPorts) >= 16 {
		s.InboundDstPortsMap = make(map[int]struct{})
		for _, v := range s.InboundDstPorts {
			s.InboundDstPortsMap[v] = struct{}{}
		}
		s.InboundDstPortsMap[val] = struct{}{}
	}
	s.InboundDstPorts = append(s.InboundDstPorts, val)
}

func (s *IPStats) UpdateIAT(diff float64) {
	s.IatCount++
	delta := diff - s.IatMean
	s.IatMean += delta / s.IatCount
	delta2 := diff - s.IatMean
	s.IatM2 += delta * delta2
}

func (s *IPStats) AddTargetStartTime(tKey TargetKey, first time.Time) {
	valTime := float64(first.UnixNano()) / 1e9

	if !s.HasFirstTarget {
		s.FirstTarget = tKey
		s.FirstTargetLastTime = valTime
		s.HasFirstTarget = true
		s.UpdateIAT(0)
		return
	}

	if s.FirstTarget == tKey {
		diff := valTime - s.FirstTargetLastTime
		s.UpdateIAT(diff)
		s.FirstTargetLastTime = valTime
		return
	}

	if s.TargetLastTimesMap != nil {
		if idx, exists := s.TargetLastTimesMap[tKey]; exists {
			diff := valTime - s.TargetLastTimes[idx].LastSeenTime
			s.UpdateIAT(diff)
			s.TargetLastTimes[idx].LastSeenTime = valTime
			return
		}

		idx := len(s.TargetLastTimes)
		tlt := TargetLastTime{
			Target:       tKey,
			LastSeenTime: valTime,
		}
		s.TargetLastTimes = append(s.TargetLastTimes, tlt)
		s.TargetLastTimesMap[tKey] = idx
		s.UpdateIAT(0)
		return
	}

	for i := range s.TargetLastTimes {
		if s.TargetLastTimes[i].Target == tKey {
			diff := valTime - s.TargetLastTimes[i].LastSeenTime
			s.UpdateIAT(diff)
			s.TargetLastTimes[i].LastSeenTime = valTime
			return
		}
	}

	if len(s.TargetLastTimes) >= 16 {
		s.TargetLastTimesMap = make(map[TargetKey]int)
		for idx, tlt := range s.TargetLastTimes {
			s.TargetLastTimesMap[tlt.Target] = idx
		}
		idx := len(s.TargetLastTimes)
		tlt := TargetLastTime{
			Target:       tKey,
			LastSeenTime: valTime,
		}
		s.TargetLastTimes = append(s.TargetLastTimes, tlt)
		s.TargetLastTimesMap[tKey] = idx
		s.UpdateIAT(0)
		return
	}

	tlt := TargetLastTime{
		Target:       tKey,
		LastSeenTime: valTime,
	}
	s.TargetLastTimes = append(s.TargetLastTimes, tlt)
	s.UpdateIAT(0)
}

func (s *IPStats) Merge(other *IPStats) {
	s.FlowCount += other.FlowCount
	s.TotalBytes += other.TotalBytes
	s.TotalPackets += other.TotalPackets
	s.TCPCount += other.TCPCount
	s.UDPCount += other.UDPCount
	s.ICMPCount += other.ICMPCount
	s.SynOnlyCount += other.SynOnlyCount
	s.RstCount += other.RstCount
	s.WellKnownPortCount += other.WellKnownPortCount
	s.SumDurationSec += other.SumDurationSec

	if other.HasFirstDstIP {
		s.AddUniqueDstIP(other.FirstDstIP)
	}
	for _, ip := range other.UniqueDstIPs {
		s.AddUniqueDstIP(ip)
	}

	if other.HasFirstDstPort {
		s.AddUniqueDstPort(other.FirstDstPort)
	}
	for _, p := range other.UniqueDstPorts {
		s.AddUniqueDstPort(p)
	}

	if other.HasFirstInbound {
		s.AddInboundDstPort(other.FirstInboundPort)
	}
	for _, p := range other.InboundDstPorts {
		s.AddInboundDstPort(p)
	}

	if other.IatCount > 0 {
		if s.IatCount == 0 {
			s.IatCount = other.IatCount
			s.IatMean = other.IatMean
			s.IatM2 = other.IatM2
		} else {
			n1 := s.IatCount
			n2 := other.IatCount
			delta := other.IatMean - s.IatMean
			s.IatCount = n1 + n2
			s.IatMean = s.IatMean + delta*n2/(n1+n2)
			s.IatM2 = s.IatM2 + other.IatM2 + delta*delta*n1*n2/(n1+n2)
		}
	}
}
