package pipeline

import (
	"fmt"
	"io"
	"os"

	"goversion/engine"
	"goversion/models"
)

type RecordProcessor interface {
	ProcessRecords([]models.NetflowRecord)
	CalculateResults() []models.MLResult
	TotalCount() int64
}

type StreamFn func(r io.Reader, fn func([]models.NetflowRecord)) error


func AnalyzeFile(inputPath string, modelPath string, stream StreamFn) ([]models.MLResult, int64, error) {
	detector, err := engine.NewDetector(modelPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}

	_, err = ProcessFile(inputPath, detector, stream)
	if err != nil {
		return nil, 0, err
	}

	results := detector.CalculateResults()
	return results, detector.TotalCount(), nil
}

func ProcessFile(inputPath string, processor RecordProcessor, stream StreamFn) (int64, error) {
	if stream == nil {
		return 0, fmt.Errorf("stream function cannot be nil")
	}

	file, err := os.Open(inputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	progressCallback := OnProgress
	if progressCallback != nil {
		reader = &ProgressReader{
			r:          file,
			OnProgress: progressCallback,
		}
	}

	if err := stream(reader, processor.ProcessRecords); err != nil {
		return 0, fmt.Errorf("failed to stream netflow data: %w", err)
	}

	return processor.TotalCount(), nil
}

func execute(r io.Reader, processor RecordProcessor, stream StreamFn) ([]models.MLResult, int64, error) {
	if stream == nil {
		return nil, 0, fmt.Errorf("stream function cannot be nil")
	}
	if err := stream(r, processor.ProcessRecords); err != nil {
		return nil, 0, fmt.Errorf("failed to stream netflow data: %w", err)
	}

	results := processor.CalculateResults()
	return results, processor.TotalCount(), nil
}
