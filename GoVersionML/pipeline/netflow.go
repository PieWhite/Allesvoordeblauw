package pipeline

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
)

type RecordProcessor interface {
	ProcessRecords([]models.NetflowRecord)
	CalculateResults() ([]models.MLResult, int)
	TotalCount() int64
}

type StreamFn func(r io.Reader, fn func([]models.NetflowRecord)) error

func AnalyzeFile(cfg *config.AppConfig, modelPath string, stream StreamFn) ([]models.MLResult, int, int64, error) {
	detector, err := engine.NewDetector(modelPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}
	if cfg != nil {
		detector.Subnet = cfg.Subnet
	}

	inputPath := ""
	if cfg != nil {
		inputPath = cfg.InputPath
	}

	_, err = ProcessFile(inputPath, detector, stream)
	if err != nil {
		return nil, 0, 0, err
	}

	results, uniqueIPs := detector.CalculateResults()
	return results, uniqueIPs, detector.TotalCount(), nil
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
			Path:       inputPath,
		}
	}

	var fileCount atomic.Int64
	err = stream(reader, func(records []models.NetflowRecord) {
		processor.ProcessRecords(records)
		fileCount.Add(int64(len(records)))
	})

	if err != nil {
		return 0, fmt.Errorf("failed to stream netflow data: %w", err)
	}

	return fileCount.Load(), nil
}

func execute(r io.Reader, processor RecordProcessor, stream StreamFn) ([]models.MLResult, int, int64, error) {
	if stream == nil {
		return nil, 0, 0, fmt.Errorf("stream function cannot be nil")
	}
	if err := stream(r, processor.ProcessRecords); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to stream netflow data: %w", err)
	}

	results, uniqueIPs := processor.CalculateResults()
	return results, uniqueIPs, processor.TotalCount(), nil
}
