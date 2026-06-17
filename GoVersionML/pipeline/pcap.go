package pipeline

import (
	"fmt"
	"io"
	"os"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
)

// PcapRecordProcessor abstracts the engine detector specifically for PCAP records
type PcapRecordProcessor interface {
	ProcessPcapRecords([]models.PcapRecord)
	CalculateResults() ([]models.MLResult, int)
	TotalCount() int64
}

type PcapStreamFn func(r io.Reader, fn func([]models.PcapRecord)) error

// AnalyzePcapFile is the entry point for PCAP file stream parsing and botnet detection
func AnalyzePcapFile(cfg *config.AppConfig, modelPath string, stream PcapStreamFn) ([]models.MLResult, int, int64, error) {
	detector, err := engine.NewPcapDetector(modelPath)
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

	_, err = ProcessPcapFile(inputPath, detector, stream)
	if err != nil {
		return nil, 0, 0, err
	}

	results, uniqueIPs := detector.CalculateResults()
	return results, uniqueIPs, detector.TotalCount(), nil
}

// ProcessPcapFile opens the raw PCAP file and streams it using the shared ProgressReader
func ProcessPcapFile(inputPath string, processor PcapRecordProcessor, stream PcapStreamFn) (int64, error) {
	if stream == nil {
		return 0, fmt.Errorf("stream function cannot be nil")
	}

	file, err := os.Open(inputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	progressCallback := OnProgress // Reuses thread-safe progress callback from pipeline/common.go
	if progressCallback != nil {
		reader = &ProgressReader{ // Reuses ProgressReader struct from pipeline/pipeline/common.go
			r:          file,
			OnProgress: progressCallback,
			Path:       inputPath,
		}
	}

	if err := stream(reader, processor.ProcessPcapRecords); err != nil {
		return 0, fmt.Errorf("failed to stream pcap data: %w", err)
	}

	return processor.TotalCount(), nil
}
