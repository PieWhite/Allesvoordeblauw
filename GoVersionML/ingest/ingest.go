package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"goversion/models"
	"goversion/scanner"
)

// ProcessInput is a factory function that automatically detects the file type,
// securely opens the resource, and routes it to the correct specialized scanner.
func ProcessInput(path string, processFn func(record models.NetflowRecord)) error {
	// 1. Determine the file type
	extension := strings.ToLower(filepath.Ext(path))

	// 2. Open the resource securely
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	switch extension {
	case ".json":
		return scanner.StreamNetflow(file, processFn)
	default:
		return fmt.Errorf("unsupported file extension: %s", extension)
	}
}
