package ingest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goversion/models"
	"goversion/scanner" // Import your actual scanner package here
)

// NetflowScanner defines the interface for streaming records.
// This allows us to swap the real scanner for a mock during testing.
type Scanner interface {
	StreamNetflow(r io.Reader, fn func([]models.NetflowRecord)) error
}

// RealScanner is the production implementation.
// It acts as an adapter that calls the package-level scanner.StreamNetflow.
type JSONScanner struct{}

func (rs *JSONScanner) StreamNetflow(r io.Reader, fn func([]models.NetflowRecord)) error {
	return scanner.StreamNetflow(r, fn)
}

// Ingestor manages the input lifecycle and dependency injection.
type Ingestor struct {
	NetflowScanner Scanner
}

// ProcessInput detects the file type, opens it, and delegates to the scanner.
func (i *Ingestor) ProcessInput(path string, processFn func([]models.NetflowRecord)) error {
	// 1. Determine the file type (case-insensitive)
	extension := strings.ToLower(filepath.Ext(path))

	// 2. Open the resource securely
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	// 3. Route to the scanner based on extension
	switch extension {
	case ".json":
		if i.NetflowScanner == nil {
			return fmt.Errorf("scanner not initialized")
		}
		return i.NetflowScanner.StreamNetflow(file, processFn)
	default:
		return fmt.Errorf("unsupported file extension: %s", extension)
	}
}
