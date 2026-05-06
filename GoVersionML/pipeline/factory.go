package pipeline

import (
	"fmt"
	"goversion/config"
	"goversion/models"
	"goversion/scanner"
	"goversion/scannerv2"
	"path/filepath"
	"strings"
)

func RunPipelineForInput(cfg *config.AppConfig) ([]models.MLResult, int64, error) {
	ext := strings.ToLower(filepath.Ext(cfg.InputPath))

	if ext == ".pcap" {
		return nil, 0, fmt.Errorf("pcap pipeline is not yet implemented")
	}
	if ext == ".ndjson" {
		return AnalyzeFile(cfg.InputPath, cfg.ModelPath, scannerv2.StreamNetflowV2)
	}
	if ext == ".json" {
		return AnalyzeFile(cfg.InputPath, cfg.ModelPath, scanner.StreamNetflow)
	}
	return nil, 0, fmt.Errorf("unsupported file extension: %s", ext)
}
