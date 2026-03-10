package main

import (
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

// Results evaluates the ML model on all aggregated IP time-windows and returns the highest score for each IP.
func (d *Detector) Results() []models.MLResult {
	// Map to track the MAXIMUM probability an IP achieved across all its 5-minute windows
	maxProbs := make(map[string]float64)

	for _, stats := range d.aggregator.IPs {
		features := stats.ToMLVector()

		// Convert to SparseMatrix required by xgboost-go
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
			log.Printf("Error predicting for %s: %v", stats.IP, err)
			continue
		}

		if len(preds.Vectors) > 0 {
			v := *preds.Vectors[0]
			if len(v) > 0 {
				prob := float64(v[0])
				// Track the highest probability seen across any 5-minute window for this IP
				if currentMax, exists := maxProbs[stats.IP]; !exists || prob > currentMax {
					maxProbs[stats.IP] = prob
				}
			}
		}
	}

	var results []models.MLResult
	for ip, prob := range maxProbs {
		isBotnet := prob > 0.50
		results = append(results, models.MLResult{
			IP:          ip,
			Probability: prob * 100.0,
			IsBotnet:    isBotnet,
		})
	}

	return results
}
