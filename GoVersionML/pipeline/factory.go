package pipeline

import (
	"fmt"
	"goversion/config"
	"goversion/models"
	"goversion/JSONScanner"
	"goversion/NDJSONScanner"
	"path/filepath"
	"strings"
)

func RunPipelineForInput(cfg *config.AppConfig) ([]models.MLResult, int64, error) {
	ext := strings.ToLower(filepath.Ext(cfg.InputPath))

	if ext == ".pcap" {
		return nil, 0, fmt.Errorf("pcap pipeline is not yet implemented")
	}
	if ext == ".ndjson" {
		return AnalyzeFile(cfg.InputPath, cfg.ModelPath, NDJSONScanner.StreamNetflowV2)
	}
	if ext == ".json" {
		return AnalyzeFile(cfg.InputPath, cfg.ModelPath, JSONScanner.StreamNetflow)
	}
	return nil, 0, fmt.Errorf("unsupported file extension: %s", ext)
}
