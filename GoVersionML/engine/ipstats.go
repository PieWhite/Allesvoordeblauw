package engine

import (
	"math"
	"sort"
)

type TargetKey struct {
	IP   string
	Port int
}

type CompactTime struct {
	IPIdx  uint16
	Port   uint16
	Offset float32
}

type IPStats struct {
	IP                 string
	Window             int64
	FlowCount          int
	UniqueDstIPs       []string
	OutboundDstPorts   []int
	InboundDstPorts    []int
	TotalBytes         float64
	TotalPackets       float64
	TCPCount           float64
	UDPCount           float64
	ICMPCount          float64
	SynOnlyCount       float64
	RstCount           float64
	WellKnownPortCount float64
	SumDurationSec     float64
	TargetStartTimes   []CompactTime

	// Private helper maps for fast O(1) deduplication on heavy scanners
	dstIPMap   map[string]int
	outPortMap map[int]struct{}
	inPortMap  map[int]struct{}
}

func NewIPStats() *IPStats {
	return &IPStats{}
}

func (s *IPStats) GetIPIdx(ip string) int {
	if len(s.UniqueDstIPs) < 16 {
		for i, existing := range s.UniqueDstIPs {
			if existing == ip {
				return i
			}
		}
		idx := len(s.UniqueDstIPs)
		s.UniqueDstIPs = append(s.UniqueDstIPs, ip)
		return idx
	}

	if s.dstIPMap == nil {
		s.dstIPMap = make(map[string]int, 32)
		for i, existing := range s.UniqueDstIPs {
			s.dstIPMap[existing] = i
		}
	}

	if idx, exists := s.dstIPMap[ip]; exists {
		return idx
	}

	idx := len(s.UniqueDstIPs)
	s.dstIPMap[ip] = idx
	s.UniqueDstIPs = append(s.UniqueDstIPs, ip)
	return idx
}

func (s *IPStats) AddOutboundDstPort(port int) {
	if len(s.OutboundDstPorts) < 16 {
		for _, existing := range s.OutboundDstPorts {
			if existing == port {
				return
			}
		}
		s.OutboundDstPorts = append(s.OutboundDstPorts, port)
		return
	}

	if s.outPortMap == nil {
		s.outPortMap = make(map[int]struct{}, 32)
		for _, existing := range s.OutboundDstPorts {
			s.outPortMap[existing] = struct{}{}
		}
	}

	if _, exists := s.outPortMap[port]; !exists {
		s.outPortMap[port] = struct{}{}
		s.OutboundDstPorts = append(s.OutboundDstPorts, port)
	}
}

func (s *IPStats) AddInboundDstPort(port int) {
	if len(s.InboundDstPorts) < 16 {
		for _, existing := range s.InboundDstPorts {
			if existing == port {
				return
			}
		}
		s.InboundDstPorts = append(s.InboundDstPorts, port)
		return
	}

	if s.inPortMap == nil {
		s.inPortMap = make(map[int]struct{}, 32)
		for _, existing := range s.InboundDstPorts {
			s.inPortMap[existing] = struct{}{}
		}
	}

	if _, exists := s.inPortMap[port]; !exists {
		s.inPortMap[port] = struct{}{}
		s.InboundDstPorts = append(s.InboundDstPorts, port)
	}
}

// ToMLVector computes the final 21 float64 features expected by XGBoost V2.
func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 21)
	}

	portSymmetry := s.calculatePortSymmetry()
	iatMean, iatVar, iatCV := s.calculateIATMetrics()

	uniqueDstIPsCount := len(s.UniqueDstIPs)
	uniqueDstPortsCount := len(s.OutboundDstPorts)

	uniquePorts := float64(uniqueDstPortsCount)
	if uniquePorts == 0 {
		uniquePorts = 1
	}

	totalPackets := s.TotalPackets
	if totalPackets == 0 {
		totalPackets = 1
	}

	pctWellKnownPorts := (s.WellKnownPortCount / fc) * 100.0

	// Pack and return the array — order matches extract_features_v2.py
	return []float64{
		fc,                                         // 0:  flow_count
		float64(uniqueDstIPsCount),                 // 1:  unique_dst_ips
		float64(uniqueDstPortsCount),               // 2:  unique_dst_ports
		s.TotalBytes,                               // 3:  total_bytes
		s.TotalPackets,                             // 4:  total_packets
		s.TotalBytes / fc,                          // 5:  avg_bytes_per_flow
		s.TotalPackets / fc,                        // 6:  avg_packets_per_flow
		(s.TCPCount / fc) * 100.0,                  // 7:  pct_tcp
		(s.UDPCount / fc) * 100.0,                  // 8:  pct_udp
		(s.ICMPCount / fc) * 100.0,                 // 9:  pct_icmp
		pctWellKnownPorts,                          // 10: pct_well_known_ports
		100.0 - pctWellKnownPorts,                  // 11: pct_high_ports
		s.SumDurationSec / fc,                      // 12: avg_duration
		iatMean,                                    // 13: iat_mean
		iatVar,                                     // 14: iat_variance
		portSymmetry,                               // 15: port_symmetry
		float64(uniqueDstIPsCount) / uniquePorts,   // 16: ip_port_ratio
		s.TotalBytes / totalPackets,                // 17: avg_payload_per_packet
		(s.SynOnlyCount / fc) * 100.0,              // 18: pct_syn_only
		(s.RstCount / fc) * 100.0,                  // 19: pct_rst
		iatCV,                                      // 20: iat_cv
	}
}

func (s *IPStats) calculatePortSymmetry() float64 {
	if len(s.OutboundDstPorts) == 0 || len(s.InboundDstPorts) == 0 {
		return 0
	}

	sort.Ints(s.OutboundDstPorts)
	sort.Ints(s.InboundDstPorts)

	var symmetry float64
	i, j := 0, 0
	for i < len(s.OutboundDstPorts) && j < len(s.InboundDstPorts) {
		if s.OutboundDstPorts[i] == s.InboundDstPorts[j] {
			symmetry++
			i++
			j++
		} else if s.OutboundDstPorts[i] < s.InboundDstPorts[j] {
			i++
		} else {
			j++
		}
	}
	return symmetry
}

func (s *IPStats) calculateIATMetrics() (mean float64, variance float64, cv float64) {
	if len(s.TargetStartTimes) == 0 {
		return 0, 0, 0
	}

	// Sort flat list by IPIdx, then Port, then Offset
	sort.Slice(s.TargetStartTimes, func(i, j int) bool {
		if s.TargetStartTimes[i].IPIdx != s.TargetStartTimes[j].IPIdx {
			return s.TargetStartTimes[i].IPIdx < s.TargetStartTimes[j].IPIdx
		}
		if s.TargetStartTimes[i].Port != s.TargetStartTimes[j].Port {
			return s.TargetStartTimes[i].Port < s.TargetStartTimes[j].Port
		}
		return s.TargetStartTimes[i].Offset < s.TargetStartTimes[j].Offset
	})

	allDiffs := make([]float64, 0, len(s.TargetStartTimes))

	i := 0
	for i < len(s.TargetStartTimes) {
		groupStart := i
		ipIdx := s.TargetStartTimes[i].IPIdx
		port := s.TargetStartTimes[i].Port

		i++
		for i < len(s.TargetStartTimes) && s.TargetStartTimes[i].IPIdx == ipIdx && s.TargetStartTimes[i].Port == port {
			i++
		}
		groupEnd := i

		// Match Python fillna(0)
		allDiffs = append(allDiffs, 0.0)

		for idx := groupStart + 1; idx < groupEnd; idx++ {
			diff := float64(s.TargetStartTimes[idx].Offset - s.TargetStartTimes[idx-1].Offset)
			allDiffs = append(allDiffs, diff)
		}
	}

	if len(allDiffs) == 0 {
		return 0, 0, 0
	}

	var sumDiffs float64
	for _, d := range allDiffs {
		sumDiffs += d
	}
	mean = sumDiffs / float64(len(allDiffs))

	var sumSqDiff float64
	for _, d := range allDiffs {
		sumSqDiff += (d - mean) * (d - mean)
	}
	if len(allDiffs) > 1 {
		variance = sumSqDiff / float64(len(allDiffs)-1)
	}

	if mean > 0 {
		cv = math.Sqrt(variance) / mean
	}

	return mean, variance, cv
}
