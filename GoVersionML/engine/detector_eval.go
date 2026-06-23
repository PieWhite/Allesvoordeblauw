// detector_eval.go handles batch evaluation of completed time windows against
// the XGBoost model. It maintains local accumulation buffers to minimize lock
// contention before merging results into the detector's global state.
package engine

import (
	"math"
	"sort"
)

func (d *Detector) evaluateBatch(statsBatch []*IPStats) {
	if len(statsBatch) == 0 {
		return
	}

	features := make([]float32, 21)
	f64 := make([]float64, 21)

	localMaxProbs := make(map[uint32]float64)
	localMaxFeatures := make(map[uint32][]float64)
	localTopBenign := make([]BenignIPInfo, 0, 10)
	localSeen := NewHyperLogLog(14)

	for _, stats := range statsBatch {
		if stats.FlowCount <= 1 {
			if localSeen != nil {
				localSeen.Add(stats.IP)
			}
			continue
		}

		for i := range features {
			features[i] = float32(math.NaN())
		}

		stats.FillMLVector(f64)

		for i, val := range f64 {
			if val != 0 {
				features[i] = float32(val)
			}
		}

		pred := d.model.PredictProba(features)
		prob := float64(pred)
		ip := stats.IP

		if localSeen != nil {
			localSeen.Add(ip)
		}

		if prob >= 0.50 {
			if currentMax, exists := localMaxProbs[ip]; !exists || prob > currentMax {
				localMaxProbs[ip] = prob
				localMaxFeatures[ip] = stats.ToMLVector()
				for i, info := range localTopBenign {
					if info.IP == ip {
						localTopBenign = append(localTopBenign[:i], localTopBenign[i+1:]...)
						break
					}
				}
			}
		} else {
			foundIdx := -1
			for i, info := range localTopBenign {
				if info.IP == ip {
					foundIdx = i
					break
				}
			}

			if foundIdx != -1 {
				if prob > localTopBenign[foundIdx].Prob {
					localTopBenign[foundIdx].Prob = prob
					localMaxFeatures[ip] = stats.ToMLVector()
					sort.Slice(localTopBenign, func(i, j int) bool {
						return localTopBenign[i].Prob > localTopBenign[j].Prob
					})
				}
			} else if len(localTopBenign) < 10 {
				localTopBenign = append(localTopBenign, BenignIPInfo{IP: ip, Prob: prob})
				localMaxFeatures[ip] = stats.ToMLVector()
				sort.Slice(localTopBenign, func(i, j int) bool {
					return localTopBenign[i].Prob > localTopBenign[j].Prob
				})
			} else if prob > localTopBenign[9].Prob {
				evictedIP := localTopBenign[9].IP
				delete(localMaxFeatures, evictedIP)
				localTopBenign[9] = BenignIPInfo{IP: ip, Prob: prob}
				localMaxFeatures[ip] = stats.ToMLVector()
				sort.Slice(localTopBenign, func(i, j int) bool {
					return localTopBenign[i].Prob > localTopBenign[j].Prob
				})
			}
		}
	}

	d.probMutex.Lock()
	if d.SeenIPs != nil && localSeen != nil {
		d.SeenIPs.Merge(localSeen)
	}
	for ip, prob := range localMaxProbs {
		if currentMax, exists := d.maxProbs[ip]; !exists || prob > currentMax {
			d.maxProbs[ip] = prob
			d.maxFeatures[ip] = localMaxFeatures[ip]
			for i, info := range d.topBenign {
				if info.IP == ip {
					d.topBenign = append(d.topBenign[:i], d.topBenign[i+1:]...)
					break
				}
			}
		}
	}
	for _, info := range localTopBenign {
		if _, exists := d.maxProbs[info.IP]; !exists {
			d.updateTopBenign(info.IP, info.Prob, nil, localMaxFeatures[info.IP])
		}
	}
	d.probMutex.Unlock()

	if len(statsBatch) > 0 && OnWindowsInferred != nil {
		OnWindowsInferred(int64(len(statsBatch)))
	}

	for _, stats := range statsBatch {
		RecycleIPStats(stats)
	}
}

func (d *Detector) updateTopBenign(ip uint32, prob float64, stats *IPStats, cachedFeatures []float64) {
	foundIdx := -1
	for i, info := range d.topBenign {
		if info.IP == ip {
			foundIdx = i
			break
		}
	}

	if foundIdx != -1 {
		if prob > d.topBenign[foundIdx].Prob {
			d.topBenign[foundIdx].Prob = prob
			if cachedFeatures != nil {
				d.maxFeatures[ip] = cachedFeatures
			} else {
				d.maxFeatures[ip] = stats.ToMLVector()
			}
			sort.Slice(d.topBenign, func(i, j int) bool {
				return d.topBenign[i].Prob > d.topBenign[j].Prob
			})
		}
		return
	}

	if len(d.topBenign) < 10 {
		d.topBenign = append(d.topBenign, BenignIPInfo{IP: ip, Prob: prob})
		if cachedFeatures != nil {
			d.maxFeatures[ip] = cachedFeatures
		} else {
			d.maxFeatures[ip] = stats.ToMLVector()
		}
		sort.Slice(d.topBenign, func(i, j int) bool {
			return d.topBenign[i].Prob > d.topBenign[j].Prob
		})
		return
	}

	minBenignProb := d.topBenign[9].Prob
	if prob > minBenignProb {
		evictedIP := d.topBenign[9].IP
		delete(d.maxFeatures, evictedIP)

		d.topBenign[9] = BenignIPInfo{IP: ip, Prob: prob}
		if cachedFeatures != nil {
			d.maxFeatures[ip] = cachedFeatures
		} else {
			d.maxFeatures[ip] = stats.ToMLVector()
		}
		sort.Slice(d.topBenign, func(i, j int) bool {
			return d.topBenign[i].Prob > d.topBenign[j].Prob
		})
	}
}
