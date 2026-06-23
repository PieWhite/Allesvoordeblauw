/*
Package pipeline handles streaming, parsing, and execution of raw PCAP files
through the botnet machine learning inference engine.
*/
package pipeline

import (
	"fmt"
	"io"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
)

type PcapRecordProcessor interface {
	ProcessPcapRecords([]models.PcapRecord)
	CalculateResults() ([]models.MLResult, int)
	TotalCount() int64
}

type PcapStreamFn func(r io.Reader, fn func([]models.PcapRecord)) error

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

func ProcessPcapFile(inputPath string, processor PcapRecordProcessor, stream PcapStreamFn) (int64, error) {
	if stream == nil {
		return 0, fmt.Errorf("stream function cannot be nil")
	}

	file, reader, err := openFileWithProgress(inputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if err := stream(reader, processor.ProcessPcapRecords); err != nil {
		return 0, fmt.Errorf("failed to stream pcap data: %w", err)
	}

	return processor.TotalCount(), nil
}
