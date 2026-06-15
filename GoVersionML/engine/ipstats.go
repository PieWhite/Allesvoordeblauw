package engine

import (
	"math"
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
	IP                 uint32
	FlowCount          int
	
	// Inline first element to avoid slice backing array allocation on heap
	HasFirstDstIP      bool
	FirstDstIP         uint32
	UniqueDstIPs       []uint32
	UniqueDstIPsMap    map[uint32]struct{}

	HasFirstDstPort    bool
	FirstDstPort       int
	UniqueDstPorts     []int
	UniqueDstPortsMap  map[int]struct{}

	HasFirstOutbound   bool
	FirstOutboundPort  int
	OutboundDstPorts   []int
	OutboundDstPortsMap map[int]struct{}

	HasFirstInbound    bool
	FirstInboundPort   int
	InboundDstPorts    []int
	InboundDstPortsMap  map[int]struct{}

	TotalBytes         float64
	TotalPackets       float64
	TCPCount           float64
	UDPCount           float64
	ICMPCount          float64
	SynOnlyCount       float64
	RstCount           float64
	WellKnownPortCount float64
	SumDurationSec     float64

	IatCount           float64
	IatMean            float64
	IatM2              float64

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

	s.HasFirstOutbound = false
	s.FirstOutboundPort = 0
	if cap(s.OutboundDstPorts) > 1024 {
		s.OutboundDstPorts = nil
	} else {
		s.OutboundDstPorts = s.OutboundDstPorts[:0]
	}
	s.OutboundDstPortsMap = nil

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

func (s *IPStats) AddOutboundDstPort(val int) {
	if !s.HasFirstOutbound {
		s.FirstOutboundPort = val
		s.HasFirstOutbound = true
		return
	}
	if s.FirstOutboundPort == val {
		return
	}
	if s.OutboundDstPortsMap != nil {
		if _, exists := s.OutboundDstPortsMap[val]; exists {
			return
		}
		s.OutboundDstPortsMap[val] = struct{}{}
		s.OutboundDstPorts = append(s.OutboundDstPorts, val)
		return
	}
	for _, v := range s.OutboundDstPorts {
		if v == val {
			return
		}
	}
	if len(s.OutboundDstPorts) >= 16 {
		s.OutboundDstPortsMap = make(map[int]struct{})
		for _, v := range s.OutboundDstPorts {
			s.OutboundDstPortsMap[v] = struct{}{}
		}
		s.OutboundDstPortsMap[val] = struct{}{}
	}
	s.OutboundDstPorts = append(s.OutboundDstPorts, val)
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

// FillMLVector populates features slice (must be length 21) with final ML features.
func (s *IPStats) FillMLVector(features []float64) {
	_ = features[20] // Bounds check elimination

	fc := float64(s.FlowCount)
	if fc == 0 {
		for i := 0; i < 21; i++ {
			features[i] = 0
		}
		return
	}

	portSymmetry := s.calculatePortSymmetry()
	iatMean, iatVar, iatCV := s.calculateIATMetrics()

	uniquePorts := float64(s.NumUniqueDstPorts())
	if uniquePorts == 0 {
		uniquePorts = 1
	}

	totalPackets := s.TotalPackets
	if totalPackets == 0 {
		totalPackets = 1
	}

	pctWellKnownPorts := (s.WellKnownPortCount / fc) * 100.0

	features[0] = fc
	features[1] = float64(s.NumUniqueDstIPs())
	features[2] = float64(s.NumUniqueDstPorts())
	features[3] = s.TotalBytes
	features[4] = s.TotalPackets
	features[5] = s.TotalBytes / fc
	features[6] = s.TotalPackets / fc
	features[7] = (s.TCPCount / fc) * 100.0
	features[8] = (s.UDPCount / fc) * 100.0
	features[9] = (s.ICMPCount / fc) * 100.0
	features[10] = pctWellKnownPorts
	features[11] = 100.0 - pctWellKnownPorts
	features[12] = s.SumDurationSec / fc
	features[13] = iatMean
	features[14] = iatVar
	features[15] = portSymmetry
	features[16] = float64(s.NumUniqueDstIPs()) / uniquePorts
	features[17] = s.TotalBytes / totalPackets
	features[18] = (s.SynOnlyCount / fc) * 100.0
	features[19] = (s.RstCount / fc) * 100.0
	features[20] = iatCV
}

func (s *IPStats) ToMLVector() []float64 {
	vec := make([]float64, 21)
	s.FillMLVector(vec)
	return vec
}

func (s *IPStats) calculatePortSymmetry() float64 {
	var symmetry float64

	hasInbound := func(p int) bool {
		if s.HasFirstInbound && s.FirstInboundPort == p {
			return true
		}
		if s.InboundDstPortsMap != nil {
			_, exists := s.InboundDstPortsMap[p]
			return exists
		}
		for _, port := range s.InboundDstPorts {
			if port == p {
				return true
			}
		}
		return false
	}

	if s.HasFirstOutbound && hasInbound(s.FirstOutboundPort) {
		symmetry++
	}

	for _, p := range s.OutboundDstPorts {
		if hasInbound(p) {
			symmetry++
		}
	}

	return symmetry
}

func (s *IPStats) calculateIATMetrics() (mean float64, variance float64, cv float64) {
	mean = s.IatMean
	if s.IatCount > 1 {
		variance = s.IatM2 / (s.IatCount - 1)
	}
	if mean > 0 {
		cv = math.Sqrt(variance) / mean
	}
	return mean, variance, cv
}
