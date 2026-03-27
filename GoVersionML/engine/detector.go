package engine

import (
	"fmt"
	"log"

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
}

func NewDetector(modelPath string) (*Detector, error) {
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}

	return &Detector{
		aggregator: NewAggregator(),
		model:      loadedModel,
	}, nil
}

func (d *Detector) ProcessRecords(records []models.NetflowRecord) {
	d.TotalRecords += int64(len(records))
	for _, record := range records {
		d.aggregator.Update(record)
	}
}

func (d *Detector) ProcessRecord(record models.NetflowRecord) {
	d.TotalRecords++
	d.aggregator.Update(record)
}

func (d *Detector) CalculateResults() []models.MLResult {
	maxProbs := make(map[string]float64)
	for _, stats := range d.aggregator.AllIPStats() {
		features := stats.ToMLVector()
		prob, err := d.predictProbability(features)
		if err != nil {
			log.Printf("Error predicting for %s: %v", stats.IP, err)
			continue
		}
		if currentMax, exists := maxProbs[stats.IP]; !exists || prob > currentMax {
			maxProbs[stats.IP] = prob
		}
	}

	return d.formatResults(maxProbs)
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
