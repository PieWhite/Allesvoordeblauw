// ipstats_ml.go provides ML feature vector generation from aggregated IP
// statistics. It computes derived metrics (port symmetry, IAT statistics,
// protocol ratios) and fills the 21-element feature vector consumed by
// the XGBoost model.
package engine

import "math"

func (s *IPStats) FillMLVector(features []float64) {
	_ = features[20]

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

	if s.HasFirstDstPort && hasInbound(s.FirstDstPort) {
		symmetry++
	}

	for _, p := range s.UniqueDstPorts {
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
