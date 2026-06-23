package engine

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"goversion/config"
	"goversion/models"
	"math"
)

// PcapDetector performs statistical evaluation on raw PCAP packets using the 39-feature model
type PcapDetector struct {
	TotalRecords      int64
	pcapWindowManager *PcapWindowManager
	model             *FastXGBoost
	maxProbs          map[uint32]float64
	maxFeatures       map[uint32][]float64
	topBenign         []BenignIPInfo
	explainer         *Explainer
	probMutex         sync.Mutex
	Subnet            string
	SeenIPs           *HyperLogLog
	evalWg            sync.WaitGroup
	completedWindows  chan []*PcapIPStats
}

func NewPcapDetector(modelPath string) (*PcapDetector, error) {
	loadedModel, err := GetOrLoadModel(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load pcap model: %w", err)
	}

	explainer, err := GetOrLoadExplainer(modelPath, PcapFeatureNames)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PCAP explainer: %w", err)
	}

	d := &PcapDetector{
		pcapWindowManager: NewPcapWindowManager(WindowFlushPolicy{Mode: WindowFlushAssumeOrdered}),
		model:             loadedModel,
		maxProbs:          make(map[uint32]float64),
		maxFeatures:       make(map[uint32][]float64),
		topBenign:         make([]BenignIPInfo, 0, 10),
		explainer:         explainer,
		SeenIPs:           NewHyperLogLog(14),
	}
	d.startWorkers()
	return d, nil
}

func (d *PcapDetector) startWorkers() {
	d.completedWindows = make(chan []*PcapIPStats, 100)
	for i := 0; i < 4; i++ {
		d.evalWg.Add(1)
		go func() {
			defer d.evalWg.Done()
			for batch := range d.completedWindows {
				d.evaluateBatch(batch)
			}
		}()
	}
}

// TotalCount returns the total number of records processed.
func (d *PcapDetector) TotalCount() int64 {
	return atomic.LoadInt64(&d.TotalRecords)
}

// ProcessPcapRecords streams a batch of PCAP records into the windowManager
func (d *PcapDetector) ProcessPcapRecords(records []models.PcapRecord) {
	var matchedCount int64
	var matchedRecords []models.PcapRecord

	if d.Subnet != "" {
		matchedRecords = make([]models.PcapRecord, 0, len(records))
		for _, record := range records {
			if !config.MatchSubnet(record.SrcIP, d.Subnet) && !config.MatchSubnet(record.DstIP, d.Subnet) {
				continue
			}
			matchedCount++
			matchedRecords = append(matchedRecords, record)
		}
	} else {
		matchedCount = int64(len(records))
		matchedRecords = records
	}

	atomic.AddInt64(&d.TotalRecords, matchedCount)
	if matchedCount > 0 && OnRecordsAggregated != nil {
		OnRecordsAggregated(matchedCount)
	}

	if len(matchedRecords) > 0 {
		flushed := d.pcapWindowManager.ProcessRecords(matchedRecords)
		if len(flushed) > 0 && d.completedWindows != nil {
			d.completedWindows <- flushed
		}
	}
}

func (d *PcapDetector) Wait() {
	d.evalWg.Wait()
}

func (d *PcapDetector) Close() {
	if d.completedWindows != nil {
		close(d.completedWindows)
	}
}

func (d *PcapDetector) SetWindowFlushMode(mode WindowFlushMode) {
	d.pcapWindowManager.policy.Mode = mode
}

func (d *PcapDetector) evaluateBatch(statsBatch []*PcapIPStats) {
	if len(statsBatch) == 0 {
		return
	}

	// Local maps to eliminate lock contention
	localMaxProbs := make(map[uint32]float64)
	localMaxFeatures := make(map[uint32][]float64)
	localTopBenign := make([]BenignIPInfo, 0, 10)
	localSeen := NewHyperLogLog(14)

	features := make([]float32, 39)
	f64 := make([]float64, 39)

	for _, stats := range statsBatch {
		for i := range features {
			features[i] = float32(math.NaN())
		}

		stats.FillPcapMLVector(f64)

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
				localMaxFeatures[ip] = stats.ToPcapMLVector()
				for i, info := range localTopBenign {
					if info.IP == ip {
						localTopBenign = append(localTopBenign[:i], localTopBenign[i+1:]...)
						break
					}
				}
			}
		} else {
			// Update local benign
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
					localMaxFeatures[ip] = stats.ToPcapMLVector()
					sort.Slice(localTopBenign, func(i, j int) bool {
						return localTopBenign[i].Prob > localTopBenign[j].Prob
					})
				}
			} else if len(localTopBenign) < 10 {
				localTopBenign = append(localTopBenign, BenignIPInfo{IP: ip, Prob: prob})
				localMaxFeatures[ip] = stats.ToPcapMLVector()
				sort.Slice(localTopBenign, func(i, j int) bool {
					return localTopBenign[i].Prob > localTopBenign[j].Prob
				})
			} else if prob > localTopBenign[9].Prob {
				evictedIP := localTopBenign[9].IP
				delete(localMaxFeatures, evictedIP)
				localTopBenign[9] = BenignIPInfo{IP: ip, Prob: prob}
				localMaxFeatures[ip] = stats.ToPcapMLVector()
				sort.Slice(localTopBenign, func(i, j int) bool {
					return localTopBenign[i].Prob > localTopBenign[j].Prob
				})
			}
		}
	}

	// Merge local results into global state with a single lock acquisition
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
}

func (d *PcapDetector) updateTopBenign(ip uint32, prob float64, stats *PcapIPStats, cachedFeatures []float64) {
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
				d.maxFeatures[ip] = stats.ToPcapMLVector()
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
			d.maxFeatures[ip] = stats.ToPcapMLVector()
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
			d.maxFeatures[ip] = stats.ToPcapMLVector()
		}
		sort.Slice(d.topBenign, func(i, j int) bool {
			return d.topBenign[i].Prob > d.topBenign[j].Prob
		})
	}
}

// Flush processes all remaining active stats currently in the aggregator
func (d *PcapDetector) Flush() {
	flushed := d.pcapWindowManager.FlushFinal()
	if len(flushed) > 0 && d.completedWindows != nil {
		d.completedWindows <- flushed
	}
}

// FlushResults flushes all remaining aggregator data, extracts the formatted
// results, then clears the accumulated maxProbs/maxFeatures maps to free memory.
// This must be called per-file in directory mode to prevent unbounded growth.
// It populates the seen map with all unique IPs encountered in this file.
func (d *PcapDetector) FlushResults(seen *HyperLogLog) []models.MLResult {
	if d.completedWindows != nil {
		d.Flush()
		close(d.completedWindows)
		d.evalWg.Wait()
	}

	d.probMutex.Lock()
	defer d.probMutex.Unlock()

	results := d.formatResults(d.maxProbs)

	if seen != nil && d.SeenIPs != nil {
		seen.Merge(d.SeenIPs)
	}

	// Reset detector state for the next file
	d.maxProbs = make(map[uint32]float64)
	d.maxFeatures = make(map[uint32][]float64)
	d.topBenign = d.topBenign[:0]
	d.pcapWindowManager = NewPcapWindowManager(d.pcapWindowManager.policy)
	d.TotalRecords = 0
	d.SeenIPs = NewHyperLogLog(14)

	d.startWorkers()

	return results
}

// CalculateResults flushes remaining records and formats output
func (d *PcapDetector) CalculateResults() ([]models.MLResult, int) {
	if d.completedWindows != nil {
		d.Flush()
		close(d.completedWindows)
		d.evalWg.Wait()
	}

	d.probMutex.Lock()
	defer d.probMutex.Unlock()

	uniqueCount := 0
	if d.SeenIPs != nil {
		uniqueCount = d.SeenIPs.Estimate()
	}
	return d.formatResults(d.maxProbs), uniqueCount
}

func (d *PcapDetector) formatResults(probs map[uint32]float64) []models.MLResult {
	const threshold = 0.50
	realResults := []models.MLResult{}

	for ip, prob := range probs {
		ipStr := FormatIPv4(ip)
		if d.Subnet != "" && !config.MatchSubnet(ipStr, d.Subnet) {
			continue
		}
		if prob > threshold {
			var expl string
			if d.explainer != nil {
				if feats, ok := d.maxFeatures[ip]; ok {
					expl = d.explainer.FormatExplanation(feats)
				}
			}
			realResults = append(realResults, models.MLResult{
				IP:          ipStr,
				Probability: prob * 100.0,
				IsBotnet:    true,
				Explanation: expl,
			})
		}
	}

	for _, info := range d.topBenign {
		ipStr := FormatIPv4(info.IP)
		if d.Subnet != "" && !config.MatchSubnet(ipStr, d.Subnet) {
			continue
		}
		if info.Prob <= threshold {
			realResults = append(realResults, models.MLResult{
				IP:          ipStr,
				Probability: info.Prob * 100.0,
				IsBotnet:    false,
			})
		}
	}

	return realResults
}
