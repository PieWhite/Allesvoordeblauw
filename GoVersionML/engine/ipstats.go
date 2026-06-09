package engine

import (
	"math"
	"sort"
)

type TargetKey struct {
	IP   string
	Port int
}

type IPStats struct {
	IP                 string
	FlowCount          int
	UniqueDstIPs       map[string]struct{}
	UniqueDstPorts     map[int]struct{}
	OutboundDstPorts   map[int]struct{}
	InboundDstPorts    map[int]struct{}
	TotalBytes         float64
	TotalPackets       float64
	TCPCount           float64
	UDPCount           float64
	ICMPCount          float64
	SynOnlyCount       float64
	RstCount           float64
	WellKnownPortCount float64
	SumDurationSec     float64
	TargetStartTimes   map[TargetKey][]float64
}

func NewIPStats() *IPStats {
	return &IPStats{}
}

func (s *IPStats) ToMLVector() []float64 {
	fc := float64(s.FlowCount)
	if fc == 0 {
		return make([]float64, 21)
	}

	portSymmetry := s.calculatePortSymmetry()
	iatMean, iatVar, iatCV := s.calculateIATMetrics()

	uniquePorts := float64(len(s.UniqueDstPorts))
	if uniquePorts == 0 {
		uniquePorts = 1
	}

	totalPackets := s.TotalPackets
	if totalPackets == 0 {
		totalPackets = 1
	}

	pctWellKnownPorts := (s.WellKnownPortCount / fc) * 100.0

	return []float64{
		fc,                             // 0:  flow_count
		float64(len(s.UniqueDstIPs)),   // 1:  unique_dst_ips
		float64(len(s.UniqueDstPorts)), // 2:  unique_dst_ports
		s.TotalBytes,                   // 3:  total_bytes
		s.TotalPackets,                 // 4:  total_packets
		s.TotalBytes / fc,              // 5:  avg_bytes_per_flow
		s.TotalPackets / fc,            // 6:  avg_packets_per_flow
		(s.TCPCount / fc) * 100.0,      // 7:  pct_tcp
		(s.UDPCount / fc) * 100.0,      // 8:  pct_udp
		(s.ICMPCount / fc) * 100.0,     // 9:  pct_icmp
		pctWellKnownPorts,              // 10: pct_well_known_ports
		100.0 - pctWellKnownPorts,      // 11: pct_high_ports
		s.SumDurationSec / fc,          // 12: avg_duration
		iatMean,                        // 13: iat_mean
		iatVar,                         // 14: iat_variance
		portSymmetry,                   // 15: port_symmetry
		float64(len(s.UniqueDstIPs)) / uniquePorts, // 16: ip_port_ratio
		s.TotalBytes / totalPackets,                // 17: avg_payload_per_packet
		(s.SynOnlyCount / fc) * 100.0,              // 18: pct_syn_only
		(s.RstCount / fc) * 100.0,                  // 19: pct_rst
		iatCV,                                      // 20: iat_cv
	}
}

func (s *IPStats) calculatePortSymmetry() float64 {
	var symmetry float64
	for p := range s.OutboundDstPorts {
		if _, ok := s.InboundDstPorts[p]; ok {
			symmetry++
		}
	}
	return symmetry
}

func (s *IPStats) calculateIATMetrics() (mean float64, variance float64, cv float64) {
	totalItems := len(s.TargetStartTimes)
	for _, times := range s.TargetStartTimes {
		if len(times) > 1 {
			totalItems += len(times) - 1
		}
	}

	allDiffs := make([]float64, 0, totalItems)

	for _, times := range s.TargetStartTimes {
		allDiffs = append(allDiffs, 0)
		if len(times) > 1 {
			sort.Float64s(times)
			for i := 1; i < len(times); i++ {
				allDiffs = append(allDiffs, times[i]-times[i-1])
			}
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
