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

type BenignIPInfo struct {
	IP   uint32
	Prob float64
}

var OnRecordsAggregated func(delta int64)
var OnWindowsInferred func(delta int64)

type Detector struct {
	TotalRecords     int64
	windowManager    *NetflowWindowManager
	model            *FastXGBoost
	maxProbs         map[uint32]float64
	maxFeatures      map[uint32][]float64
	topBenign        []BenignIPInfo
	explainer        *Explainer
	probMutex        sync.Mutex
	Subnet           string
	SeenIPs          *HyperLogLog
	evalWg           sync.WaitGroup
	completedWindows chan []*IPStats
}

func NewDetector(modelPath string) (*Detector, error) {
	loadedModel, err := GetOrLoadModel(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}

	explainer, err := GetOrLoadExplainer(modelPath, FeatureNames)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize explainer: %w", err)
	}

	d := &Detector{
		windowManager: NewNetflowWindowManager(WindowFlushPolicy{Mode: WindowFlushAssumeOrdered}),
		model:         loadedModel,
		maxProbs:      make(map[uint32]float64),
		maxFeatures:   make(map[uint32][]float64),
		topBenign:     make([]BenignIPInfo, 0, 10),
		explainer:     explainer,
		SeenIPs:       NewHyperLogLog(14),
	}
	d.startWorkers()
	return d, nil
}

func (d *Detector) startWorkers() {
	d.completedWindows = make(chan []*IPStats, 100)
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

func (d *Detector) Clone() *Detector {
	clone := &Detector{
		windowManager: NewNetflowWindowManager(d.windowManager.policy),
		model:         d.model, // Shared read-only pointer
		maxProbs:      make(map[uint32]float64),
		maxFeatures:   make(map[uint32][]float64),
		topBenign:     make([]BenignIPInfo, 0, 10),
		explainer:     d.explainer, // Shared read-only pointer
		SeenIPs:       NewHyperLogLog(14),
		Subnet:        d.Subnet,
	}
	clone.startWorkers()
	return clone
}

func (d *Detector) Merge(other *Detector) {
	d.probMutex.Lock()
	defer d.probMutex.Unlock()
	other.probMutex.Lock()
	defer other.probMutex.Unlock()

	// Merge total records count
	atomic.AddInt64(&d.TotalRecords, other.TotalRecords)

	// Merge SeenIPs
	if other.SeenIPs != nil && d.SeenIPs != nil {
		d.SeenIPs.Merge(other.SeenIPs)
	}

	// Merge aggregator
	d.windowManager.aggregator.Merge(other.windowManager.aggregator)

	// Merge maxProbs & maxFeatures
	for ip, prob := range other.maxProbs {
		if currentMax, exists := d.maxProbs[ip]; !exists || prob > currentMax {
			d.maxProbs[ip] = prob
			d.maxFeatures[ip] = other.maxFeatures[ip]
		}
	}

	// Merge topBenign
	for _, info := range other.topBenign {
		if _, exists := d.maxProbs[info.IP]; !exists {
			d.updateTopBenign(info.IP, info.Prob, nil, other.maxFeatures[info.IP])
		}
	}
}

func (d *Detector) ProcessRecord(record models.NetflowRecord) {
	if d.Subnet != "" && !config.MatchSubnet(record.Src4Addr, d.Subnet) && !config.MatchSubnet(record.Dst4Addr, d.Subnet) {
		return
	}
	atomic.AddInt64(&d.TotalRecords, 1)
	d.windowManager.aggregator.Update(record)
}

// TotalCount returns the total number of records processed.
// This allows Detector to satisfy the pipeline.RecordProcessor interface.
func (d *Detector) TotalCount() int64 {
	return atomic.LoadInt64(&d.TotalRecords)
}

func (d *Detector) ProcessRecords(records []models.NetflowRecord) {
	var matchedCount int64
	var matchedRecords []models.NetflowRecord

	if d.Subnet != "" {
		matchedRecords = make([]models.NetflowRecord, 0, len(records))
		for _, record := range records {
			if !config.MatchSubnet(record.Src4Addr, d.Subnet) && !config.MatchSubnet(record.Dst4Addr, d.Subnet) {
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
		flushed := d.windowManager.ProcessRecords(matchedRecords)
		if len(flushed) > 0 && d.completedWindows != nil {
			d.completedWindows <- flushed
		}
	}
}

func (d *Detector) Wait() {
	d.evalWg.Wait()
}

func (d *Detector) Close() {
	if d.completedWindows != nil {
		close(d.completedWindows)
	}
}

func (d *Detector) SetWindowFlushMode(mode WindowFlushMode) {
	d.windowManager.policy.Mode = mode
}

func (d *Detector) evaluateBatch(statsBatch []*IPStats) {
	if len(statsBatch) == 0 {
		return
	}

	features := make([]float32, 21)
	f64 := make([]float64, 21)

	// Local maps to eliminate lock contention
	localMaxProbs := make(map[uint32]float64)
	localMaxFeatures := make(map[uint32][]float64)
	localTopBenign := make([]BenignIPInfo, 0, 10)
	localSeen := NewHyperLogLog(14)

	for _, stats := range statsBatch {
		// Pre-fill features with NaN as required by FastXGBoost for missing values
		for i := range features {
			features[i] = float32(math.NaN())
		}

		stats.FillMLVector(f64)
		
		// Map non-zero values to our features array
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
				// Remove from benign if present
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
		// Only add to global benign if not already a known bot
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

func (d *Detector) Flush() {
	flushed := d.windowManager.FlushFinal()
	if len(flushed) > 0 && d.completedWindows != nil {
		d.completedWindows <- flushed
	}
}

// FlushResults flushes all remaining aggregator data, extracts the formatted
// results, then clears the accumulated maxProbs/maxFeatures maps to free memory.
// This must be called per-file in directory mode to prevent unbounded growth.
// It populates the seen map with all unique IPs encountered in this file.
func (d *Detector) FlushResults(seen *HyperLogLog) []models.MLResult {
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
	d.windowManager = NewNetflowWindowManager(d.windowManager.policy)
	d.TotalRecords = 0
	d.SeenIPs = NewHyperLogLog(14)

	d.startWorkers()

	return results
}

func (d *Detector) CalculateResults() ([]models.MLResult, int) {
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

func (d *Detector) formatResults(probs map[uint32]float64) []models.MLResult {
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
