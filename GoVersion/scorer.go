package main

import (
	"math"
	"sort"
)

// Scorer tracks triggered features per IP and computes weighted risk scores.
type Scorer struct {
	weights             map[string]float64
	totalPossibleWeight float64
	ipFeatures          map[string]map[string]bool // src_ip → set of triggered rule names
}

// NewScorer creates a Scorer from the config weights.
func NewScorer(config *Config) *Scorer {
	weights := map[string]float64{
		FeatureFrequencyOfConnections: config.Weights.FrequencyOfConnections,
		FeatureIPReuse:                config.Weights.IPReuseRepeatedConnections,
		FeatureP2P:                    config.Weights.P2PC2Communications,
		FeatureSuspiciousPorts:        config.Weights.C2SuspiciousPorts,
		FeatureKnownProxies:           config.Weights.C2KnownProxies,
		FeatureSmallPackets:           config.Weights.C2SmallPackets,
	}

	var totalWeight float64
	for _, w := range weights {
		totalWeight += w
	}

	return &Scorer{
		weights:             weights,
		totalPossibleWeight: totalWeight,
		ipFeatures:          make(map[string]map[string]bool),
	}
}

// TriggerFeature marks a feature as triggered for a given IP. Idempotent.
func (s *Scorer) TriggerFeature(ip, feature string) {
	if s.ipFeatures[ip] == nil {
		s.ipFeatures[ip] = make(map[string]bool)
	}
	s.ipFeatures[ip][feature] = true
}

// Results computes risk scores and returns them sorted by risk factor descending.
func (s *Scorer) Results() []IPScore {
	var results []IPScore

	for ip, features := range s.ipFeatures {
		var weightedScore float64
		for feature := range features {
			if w, ok := s.weights[feature]; ok {
				weightedScore += w
			}
		}

		riskFactor := (weightedScore / s.totalPossibleWeight) * 100
		riskFactor = math.Round(riskFactor*100) / 100
		if riskFactor > 100 {
			riskFactor = 100
		}

		if riskFactor > 0 {
			results = append(results, IPScore{
				IP:               ip,
				TriggeredReasons: features,
				RiskFactor:       riskFactor,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskFactor > results[j].RiskFactor
	})

	return results
}

// TotalPossibleWeight returns the sum of all configured weights.
func (s *Scorer) TotalPossibleWeight() float64 {
	return s.totalPossibleWeight
}
