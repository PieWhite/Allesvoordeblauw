package main

import (
	"fmt"
	"log"

	"goversion/models"

	xgboost "github.com/Elvenson/xgboost-go"
	"github.com/Elvenson/xgboost-go/activation"
	"github.com/Elvenson/xgboost-go/inference"
	"github.com/Elvenson/xgboost-go/mat"
)

type Detector struct {
	TotalRecords int64
	aggregator   *Aggregator
	model        *inference.Ensemble
}

func NewDetector(modelPath string) *Detector {
	log.Printf("Loading XGBoost JSON dump from %s...", modelPath)

	// Binary classification so numClasses=1, and we used max_depth=6 in python
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		log.Fatalf("Error loading XGBoost JSON dump: %v", err)
	}

	return &Detector{
		aggregator: NewAggregator(),
		model:      loadedModel,
	}
}

func (d *Detector) ProcessRecord(record models.NetflowRecord) {
	d.TotalRecords++
	d.aggregator.Update(record)
}

// Results evaluates the ML model and returns the highest score for each IP.
func (d *Detector) Results() []models.MLResult {
	maxProbs := make(map[string]float64)

	// 1. Evaluate all records
	for _, stats := range d.aggregator.IPs {
		features := stats.ToMLVector()

		// We hid all the XGBoost complexity inside this clean helper!
		prob, err := d.predictProbability(features)
		if err != nil {
			log.Printf("Error predicting for %s: %v", stats.IP, err)
			continue
		}

		// Track the highest probability seen for this IP
		if currentMax, exists := maxProbs[stats.IP]; !exists || prob > currentMax {
			maxProbs[stats.IP] = prob
		}
	}

	// 2. Format the final output
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
	// 1. The Plumbing: Convert dense float64 slice to XGBoost's SparseMatrix
	sv := make(mat.SparseVector)
	for i, val := range features {
		if val != 0 {
			sv[i] = float32(val)
		}
	}

	input := mat.SparseMatrix{
		Vectors: []mat.SparseVector{sv},
	}
	// 2. The Engine: Let the library do the actual ML inference
	preds, err := d.model.PredictProba(input)
	if err != nil {
		return 0, err
	}
	// 3. The Unpacking: Digging through the nested XGBoost response
	if len(preds.Vectors) > 0 {
		v := *preds.Vectors[0]
		if len(v) > 0 {
			return float64(v[0]), nil
		}
	}

	return 0, fmt.Errorf("model returned empty prediction vectors")
}
