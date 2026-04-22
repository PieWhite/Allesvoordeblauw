package pipeline

import (
	"fmt"
	"goversion/engine"
	"goversion/models"
	"goversion/scannerv2"
	"os"
)

func RunNetflow(inputPath string, modelPath string) ([]models.MLResult, int64, error) {

	detector, err := engine.NewDetector(modelPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}

	file, err := os.Open(inputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	scannerv2.StreamNetflowV2(file, detector.ProcessRecords)
	// scanner.StreamNetflow(file, detector.ProcessRecords)

	results := detector.CalculateResults()
	return results, detector.TotalRecords, nil
}
