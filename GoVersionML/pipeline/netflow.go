package pipeline

import (
	"fmt"
	"io"
	"os"

	"goversion/engine"
	"goversion/models"
	"goversion/scannerv2"
)

type RecordProcessor interface {
	ProcessRecords([]models.NetflowRecord)
	CalculateResults() []models.MLResult
	TotalCount() int64
}

type StreamFn func(r io.Reader, fn func([]models.NetflowRecord)) error

func AnalyzeFile(inputPath string, modelPath string) ([]models.MLResult, int64, error) {
	detector, err := engine.NewDetector(modelPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}

	file, err := os.Open(inputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	return execute(file, detector, scannerv2.StreamNetflowV2)
}

func execute(r io.Reader, processor RecordProcessor, stream StreamFn) ([]models.MLResult, int64, error) {
	if err := stream(r, processor.ProcessRecords); err != nil {
		return nil, 0, fmt.Errorf("failed to stream netflow data: %w", err)
	}

	results := processor.CalculateResults()
	return results, processor.TotalCount(), nil
}
