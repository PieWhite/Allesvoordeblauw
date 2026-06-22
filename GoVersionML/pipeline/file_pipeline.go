/*
Package pipeline orchestrates the processing pipelines for different network data files,
supporting Netflow (JSON/NDJSON/CSV) and raw PCAP formats.
*/
package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
	"goversion/scanner"
)

type FilePipelineResult struct {
	Path         string
	Results      []models.MLResult
	UniqueIPs    int
	TotalRecords int64
	Err          error
}

func RunNetflowFilePipeline(ctx context.Context, path string, cfg *config.AppConfig) FilePipelineResult {
	res := FilePipelineResult{Path: path}

	ext := strings.ToLower(filepath.Ext(path))
	var streamFn StreamFn
	switch ext {
	case ".csv":
		streamFn = scanner.StreamCSV
	case ".json":
		streamFn = scanner.StreamJSON
	case ".ndjson":
		streamFn = scanner.StreamNDJSON
	default:
		res.Err = fmt.Errorf("unsupported file extension: %s", ext)
		return res
	}

	detector, err := engine.NewDetector(resolveModelPath(false))
	if err != nil {
		res.Err = fmt.Errorf("failed loading xgboost model: %w", err)
		return res
	}
	if cfg != nil {
		detector.Subnet = cfg.Subnet
	}

	count, err := ProcessFile(path, detector, streamFn)
	if err != nil {
		res.Err = err
		return res
	}

	results, uniqueIPs := detector.CalculateResults()
	res.Results = results
	res.UniqueIPs = uniqueIPs
	res.TotalRecords = count
	return res
}

func RunPcapFilePipeline(ctx context.Context, path string, cfg *config.AppConfig) FilePipelineResult {
	res := FilePipelineResult{Path: path}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pcap" {
		res.Err = fmt.Errorf("unsupported file extension: %s", ext)
		return res
	}

	detector, err := engine.NewPcapDetector(resolveModelPath(true))
	if err != nil {
		res.Err = fmt.Errorf("failed loading xgboost model: %w", err)
		return res
	}
	if cfg != nil {
		detector.Subnet = cfg.Subnet
	}

	count, err := ProcessPcapFile(path, detector, scanner.StreamPCAP)
	if err != nil {
		res.Err = err
		return res
	}

	results, uniqueIPs := detector.CalculateResults()
	res.Results = results
	res.UniqueIPs = uniqueIPs
	res.TotalRecords = count
	return res
}
