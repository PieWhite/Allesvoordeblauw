package pipeline

import (
	"fmt"
	"path/filepath"
	"strings"

	"goversion/config"
)

func GetPipelineForInput(cfg *config.AppConfig) (ScannerPipeline, error) {
	ext := strings.ToLower(filepath.Ext(cfg.InputPath))

	if ext == ".pcap" {
		return nil, fmt.Errorf("pcap pipeline is not yet implemented")
	}
	if ext == ".json" || ext == ".ndjson" {
		return NewNetflowPipeline(cfg.ModelPath), nil
	}

	return nil, fmt.Errorf("unsupported file extension: %s", ext)
}
