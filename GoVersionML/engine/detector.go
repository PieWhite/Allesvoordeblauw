// detector.go orchestrates botnet detection by processing Netflow records
// through time-windowed aggregation and XGBoost model evaluation. It manages
// the detection lifecycle including record ingestion, worker pool coordination,
// and detector cloning for concurrent file processing.
package engine

import (
	"fmt"
	"sync"
	"sync/atomic"

	"goversion/config"
	"goversion/models"
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
	for i := 0; i < 8; i++ {
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
		model:         d.model,
		maxProbs:      make(map[uint32]float64),
		maxFeatures:   make(map[uint32][]float64),
		topBenign:     make([]BenignIPInfo, 0, 10),
		explainer:     d.explainer,
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

	atomic.AddInt64(&d.TotalRecords, other.TotalRecords)

	if other.SeenIPs != nil && d.SeenIPs != nil {
		d.SeenIPs.Merge(other.SeenIPs)
	}

	d.windowManager.aggregator.Merge(other.windowManager.aggregator)

	for ip, prob := range other.maxProbs {
		if currentMax, exists := d.maxProbs[ip]; !exists || prob > currentMax {
			d.maxProbs[ip] = prob
			d.maxFeatures[ip] = other.maxFeatures[ip]
		}
	}

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

func (d *Detector) Flush() {
	flushed := d.windowManager.FlushFinal()
	if len(flushed) > 0 && d.completedWindows != nil {
		d.completedWindows <- flushed
	}
}
