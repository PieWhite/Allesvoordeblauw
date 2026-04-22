package pipeline

import (
	"fmt"

	"goversion/engine"
	"goversion/ingest"
	"goversion/models"
)

// NetflowPipeline encapsulates the process of reading netflow-like data and passing it to the ML engine.
type NetflowPipeline struct {
	modelPath string
}

func NewNetflowPipeline(modelPath string) *NetflowPipeline {
	return &NetflowPipeline{
		modelPath: modelPath,
	}
}

// Run executes the entire extraction to detection pipeline for netflow files.
func (p *NetflowPipeline) Run(inputPath string) ([]models.MLResult, int64, error) {
	// Initialize specific netflow components
	detector, err := engine.NewDetector(p.modelPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}

	flowIngestor := ingest.NewIngestor()

	// Execute processing loop
	err = flowIngestor.ProcessInput(inputPath, detector.ProcessRecords)
	if err != nil {
		return nil, 0, fmt.Errorf("scanning input file: %w", err)
	}

	// Calculate and return results
	results := detector.CalculateResults()
	return results, detector.TotalRecords, nil
}
