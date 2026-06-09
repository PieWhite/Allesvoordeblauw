package engine

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"

	"goversion/models"

	xgboost "github.com/Elvenson/xgboost-go"
	"github.com/Elvenson/xgboost-go/activation"
	"github.com/Elvenson/xgboost-go/mat"
)

// PcapDetector performs statistical evaluation on raw PCAP packets using the 39-feature model
type PcapDetector struct {
	TotalRecords   int64
	pcapAggregator *PcapAggregator
	model          XGBoostModel

	maxProbs      map[string]float64
	maxFeatures   map[string][]float64
	explainer     *Explainer
	probMutex     sync.Mutex
	currentWindow atomic.Int64
}

func NewPcapDetector(modelPath string) (*PcapDetector, error) {
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		return nil, fmt.Errorf("failed to load PCAP model: %w", err)
	}

	explainer, err := NewExplainer(modelPath, PcapFeatureNames)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PCAP explainer: %w", err)
	}

	return &PcapDetector{
		pcapAggregator: NewPcapAggregator(),
		model:          loadedModel,
		maxProbs:       make(map[string]float64),
		maxFeatures:    make(map[string][]float64),
		explainer:      explainer,
	}, nil
}

// TotalCount returns the total number of records processed.
func (d *PcapDetector) TotalCount() int64 {
	return atomic.LoadInt64(&d.TotalRecords)
}

// ProcessPcapRecords streams a batch of PCAP records into the pcapAggregator
func (d *PcapDetector) ProcessPcapRecords(records []models.PcapRecord) {
	atomic.AddInt64(&d.TotalRecords, int64(len(records)))

	var localMaxWindow int64

	for _, record := range records {
		d.pcapAggregator.Update(record)

		// Sniff timestamp for flushing logic (5-minute windows)
		win := int64(record.Timestamp) / 300 * 300
		if win > localMaxWindow {
			localMaxWindow = win
		}
	}

	if localMaxWindow > 0 {
		d.updateMaxWindowAndFlush(localMaxWindow)
	}
}

func (d *PcapDetector) updateMaxWindowAndFlush(win int64) {
	curr := d.currentWindow.Load()
	for win > curr {
		if d.currentWindow.CompareAndSwap(curr, win) {
			// Flush data older than (maxWindow - 5 minutes)
			d.flushOldWindows(win - 300)
			break
		}
		curr = d.currentWindow.Load()
	}
}

func (d *PcapDetector) flushOldWindows(threshold int64) {
	flushed := d.pcapAggregator.FlushWindow(threshold)
	if len(flushed) == 0 {
		return
	}

	d.evaluateBatch(flushed)
}

func (d *PcapDetector) evaluateBatch(statsBatch []*PcapIPStats) {
	if len(statsBatch) == 0 {
		return
	}

	vectors := make([]mat.SparseVector, len(statsBatch))

	// Worker pool: cap concurrency to NumCPU to avoid scheduler flooding on large batches
	type job struct {
		idx   int
		stats *PcapIPStats
	}
	numWorkers := runtime.NumCPU()
	if numWorkers > len(statsBatch) {
		numWorkers = len(statsBatch)
	}
	jobs := make(chan job, len(statsBatch))
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				features := j.stats.ToPcapMLVector()
				sv := make(mat.SparseVector)
				for fIdx, val := range features {
					if val != 0 {
						sv[fIdx] = float32(val)
					}
				}
				vectors[j.idx] = sv
			}
		}()
	}
	for idx, stats := range statsBatch {
		jobs <- job{idx: idx, stats: stats}
	}
	close(jobs)
	wg.Wait()

	input := mat.SparseMatrix{
		Vectors: vectors,
	}

	preds, err := d.model.PredictProba(input)
	if err != nil {
		log.Printf("Error in PCAP batch prediction: %v", err)
		return
	}

	d.probMutex.Lock()
	for idx, vPtr := range preds.Vectors {
		if vPtr == nil || len(*vPtr) == 0 {
			continue
		}
		prob := float64((*vPtr)[0])
		ip := statsBatch[idx].IP

		if currentMax, exists := d.maxProbs[ip]; !exists || prob > currentMax {
			d.maxProbs[ip] = prob
			d.maxFeatures[ip] = statsBatch[idx].ToPcapMLVector()
		}
	}
	d.probMutex.Unlock()
}

// Flush processes all remaining active stats currently in the aggregator
func (d *PcapDetector) Flush() {
	flushed := d.pcapAggregator.FlushAll()
	if len(flushed) > 0 {
		d.evaluateBatch(flushed)
	}
}

// CalculateResults flushes remaining records and formats output
func (d *PcapDetector) CalculateResults() []models.MLResult {
	d.Flush()

	d.probMutex.Lock()
	defer d.probMutex.Unlock()
	return d.formatResults(d.maxProbs)
}

func (d *PcapDetector) formatResults(probs map[string]float64) []models.MLResult {
	const threshold = 0.50
	results := make([]models.MLResult, 0, len(probs))
	for ip, prob := range probs {
		var expl string
		if prob > threshold && d.explainer != nil {
			if feats, ok := d.maxFeatures[ip]; ok {
				expl = d.explainer.FormatExplanation(feats)
			}
		}
		results = append(results, models.MLResult{
			IP:          ip,
			Probability: prob * 100.0,
			IsBotnet:    prob > threshold,
			Explanation: expl,
		})
	}
	return results
}
