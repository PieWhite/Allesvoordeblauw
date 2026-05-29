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
	maxFeatures   map[string][]float64
	explainer     *Explainer
	probMutex     sync.Mutex
	currentWindow atomic.Int64
}

func NewDetector(modelPath string) (*Detector, error) {
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}

	explainer, err := NewExplainer(modelPath, FeatureNames)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize explainer: %w", err)
	}

	return &Detector{
		aggregator:  NewAggregator(),
		model:       loadedModel,
		maxProbs:    make(map[string]float64),
		maxFeatures: make(map[string][]float64),
		explainer:   explainer,
	}, nil
}

func (d *Detector) ProcessRecord(record models.NetflowRecord) {
	atomic.AddInt64(&d.TotalRecords, 1)
	d.aggregator.Update(record)
}

// TotalCount returns the total number of records processed.
// This allows Detector to satisfy the pipeline.RecordProcessor interface.
func (d *Detector) TotalCount() int64 {
	return atomic.LoadInt64(&d.TotalRecords)
}

func (d *Detector) ProcessRecords(records []models.NetflowRecord) {
	atomic.AddInt64(&d.TotalRecords, int64(len(records)))

	var localMaxWindow int64

	for _, record := range records {
		d.aggregator.Update(record)

		// Quickly sniff the timestamp for flushing logic
		if len(record.First) >= 23 && record.First[4] == '-' && record.First[10] == 'T' {
			s := record.First
			year := int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
			month := int(s[5]-'0')*10 + int(s[6]-'0')
			day := int(s[8]-'0')*10 + int(s[9]-'0')
			hour := int(s[11]-'0')*10 + int(s[12]-'0')
			minute := int(s[14]-'0')*10 + int(s[15]-'0')
			second := int(s[17]-'0')*10 + int(s[18]-'0')

			t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
			win := t.Truncate(5 * time.Minute).Unix()
			if win > localMaxWindow {
				localMaxWindow = win
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
			// Flush data older than (maxWindow - 5 minutes)
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

	d.evaluateBatch(flushed)
}

func (d *Detector) evaluateBatch(statsBatch []*IPStats) {
	if len(statsBatch) == 0 {
		return
	}

	vectors := make([]mat.SparseVector, len(statsBatch))
	for idx, stats := range statsBatch {
		features := stats.ToMLVector()
		sv := make(mat.SparseVector)
		for i, val := range features {
			if val != 0 {
				sv[i] = float32(val)
			}
		}
		vectors[idx] = sv
	}

	input := mat.SparseMatrix{
		Vectors: vectors,
	}

	preds, err := d.model.PredictProba(input)
	if err != nil {
		log.Printf("Error in batch prediction: %v", err)
		return
	}

	d.probMutex.Lock()
	if d.maxProbs == nil {
		d.maxProbs = make(map[string]float64)
	}
	if d.maxFeatures == nil {
		d.maxFeatures = make(map[string][]float64)
	}
	for idx, vPtr := range preds.Vectors {
		if vPtr == nil || len(*vPtr) == 0 {
			continue
		}
		prob := float64((*vPtr)[0])
		ip := statsBatch[idx].IP

		if currentMax, exists := d.maxProbs[ip]; !exists || prob > currentMax {
			d.maxProbs[ip] = prob
			d.maxFeatures[ip] = statsBatch[idx].ToMLVector()
		}
	}
	d.probMutex.Unlock()
}

func (d *Detector) Flush() {
	flushed := d.aggregator.FlushAll()
	if len(flushed) > 0 {
		d.evaluateBatch(flushed)
	}
}

func (d *Detector) CalculateResults() []models.MLResult {
	d.Flush()

	d.probMutex.Lock()
	defer d.probMutex.Unlock()
	return d.formatResults(d.maxProbs)
}

func (d *Detector) formatResults(probs map[string]float64) []models.MLResult {
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
