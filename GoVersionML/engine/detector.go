package engine

import (
	"fmt"
	"log"

	"goversion/models"

	xgboost "github.com/Elvenson/xgboost-go"
	"github.com/Elvenson/xgboost-go/activation"
	"github.com/Elvenson/xgboost-go/inference"
	"github.com/Elvenson/xgboost-go/mat"
)

// Detector is the main ML inference engine. It aggregates netflow records and
// runs the XGBoost model to produce per-IP botnet probability scores.
type Detector struct {
	TotalRecords int64
	aggregator   *Aggregator
	model        *inference.Ensemble
}

// NewDetector loads the XGBoost model and returns a ready-to-use Detector.
func NewDetector(modelPath string) *Detector {
	log.Printf("Loading XGBoost JSON dump from %s...", modelPath)

	// Binary classification, max_depth=6 matches training config
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		log.Fatalf("Error loading XGBoost JSON dump: %v", err)
	}

	return &Detector{
		aggregator: NewAggregator(),
		model:      loadedModel,
	}
}

// ProcessRecord feeds a single netflow record into the aggregator.
func (d *Detector) ProcessRecord(record models.NetflowRecord) {
	d.TotalRecords++
	d.aggregator.Update(record)
}

// Results evaluates the ML model and returns the highest score per IP.
func (d *Detector) Results() []models.MLResult {
	maxProbs := make(map[string]float64)

	// Evaluate all window-level records
	for _, stats := range d.aggregator.IPs {
		features := stats.ToMLVector()

		prob, err := d.predictProbability(features)
		if err != nil {
			log.Printf("Error predicting for %s: %v", stats.IP, err)
			continue
		}

		// Track the highest probability seen for this IP across all windows
		if currentMax, exists := maxProbs[stats.IP]; !exists || prob > currentMax {
			maxProbs[stats.IP] = prob
		}
	}

	// Format the final output
	var results []models.MLResult
	for ip, prob := range maxProbs {
		results = append(results, models.MLResult{
			IP:          ip,
			Probability: prob * 100.0,
			IsBotnet:    prob > 0.50,
		})
	}

	return results
}

func (d *Detector) predictProbability(features []float64) (float64, error) {
	// Convert dense float64 slice to XGBoost's SparseMatrix format
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
