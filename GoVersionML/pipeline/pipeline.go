package pipeline

import (
	"goversion/models"
)

// ScannerPipeline defines the interface for an end-to-end processing pipeline.
type ScannerPipeline interface {
	Run(inputPath string) ([]models.MLResult, int64, error)
}
