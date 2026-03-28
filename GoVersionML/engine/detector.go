package engine

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"goversion/models"

	xgboost "github.com/Elvenson/xgboost-go"
	"github.com/Elvenson/xgboost-go/activation"
	"github.com/Elvenson/xgboost-go/mat"
)

type XGBoostModel interface {
	PredictProba(input mat.SparseMatrix) (mat.Matrix, error)
}

type Detector struct {
	TotalRecords int64
	aggregator   *Aggregator
	model        XGBoostModel

	maxProbs      map[string]float64
	probMutex     sync.Mutex
	currentWindow atomic.Int64
}

func NewDetector(modelPath string) (*Detector, error) {
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}

	return &Detector{
		aggregator: NewAggregator(),
		model:      loadedModel,
		maxProbs:   make(map[string]float64),
	}, nil
}

func (d *Detector) ProcessRecord(record models.NetflowRecord) {
	atomic.AddInt64(&d.TotalRecords, 1)
	d.aggregator.Update(record)
}

func (d *Detector) ProcessRecords(records []models.NetflowRecord) {
	atomic.AddInt64(&d.TotalRecords, int64(len(records)))

	var localMaxWindow int64

	for _, record := range records {
		d.aggregator.Update(record)

		// Quickly sniff the timestamp for flushing logic
		if len(record.First) >= 23 {
			if t, err := time.Parse("2006-01-02T15:04:05.000", record.First); err == nil {
				win := t.Truncate(5 * time.Minute).Unix()
				if win > localMaxWindow {
					localMaxWindow = win
				}
			}
		}
	}

	if localMaxWindow > 0 {
		d.updateMaxWindowAndFlush(localMaxWindow)
	}
}

func (d *Detector) updateMaxWindowAndFlush(win int64) {
	curr := d.currentWindow.Load()
	for win > curr {
		if d.currentWindow.CompareAndSwap(curr, win) {
			// We advanced the global maximum window.
			// Flush data older than (maxWindow - 10 minutes)
			d.flushOldWindows(win - 300)
			break
		}
		curr = d.currentWindow.Load()
	}
}

func (d *Detector) flushOldWindows(threshold int64) {
	flushed := d.aggregator.ExtractAndFlushBefore(threshold)
	if len(flushed) == 0 {
		return
	}

	for _, stats := range flushed {
		d.evaluateStats(stats)
	}
}

func (d *Detector) evaluateStats(stats *IPStats) {
	features := stats.ToMLVector()

	prob, err := d.predictProbability(features)
	if err != nil {
		log.Printf("Error predicting for %s: %v", stats.IP, err)
		return
	}

	d.probMutex.Lock()
	if currentMax, exists := d.maxProbs[stats.IP]; !exists || prob > currentMax {
		d.maxProbs[stats.IP] = prob
	}
	d.probMutex.Unlock()
}

func (d *Detector) CalculateResults() []models.MLResult {
	// 1. Flush any remaining data from the Aggregator
	remaining := d.aggregator.AllIPStats()
	for _, stats := range remaining {
		d.evaluateStats(stats)
	}

	d.probMutex.Lock()
	defer d.probMutex.Unlock()
	return d.formatResults(d.maxProbs)
}

func (d *Detector) formatResults(probs map[string]float64) []models.MLResult {
	const threshold = 0.50
	results := make([]models.MLResult, 0, len(probs))
	for ip, prob := range probs {
		results = append(results, models.MLResult{
			IP:          ip,
			Probability: prob * 100.0,
			IsBotnet:    prob > threshold,
		})
	}

	return results
}

func (d *Detector) predictProbability(features []float64) (float64, error) {
	sv := make(mat.SparseVector)
	for i, val := range features {
		if val != 0 {
			sv[i] = float32(val)
		}
	}

	input := mat.SparseMatrix{
		Vectors: []mat.SparseVector{sv},
	}

	preds, err := d.model.PredictProba(input)
	if err != nil {
		return 0, err
	}

	if len(preds.Vectors) > 0 {
		v := *preds.Vectors[0]
		if len(v) > 0 {
			return float64(v[0]), nil
		}
	}

	return 0, fmt.Errorf("model returned empty prediction vectors")
}
