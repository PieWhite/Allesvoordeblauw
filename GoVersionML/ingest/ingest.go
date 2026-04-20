package ingest

import (
	"fmt"
	"goversion/models"
	"goversion/scannerv2"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ScannerInterface interface {
	StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error
}

type JSONScanner struct{}

func (js *JSONScanner) StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error {
	return scannerv2.StreamNetflowV2(r, fn)
}

type Ingestor struct {
	scanners map[string]ScannerInterface
}

func NewIngestor() *Ingestor {
	return &Ingestor{
		scanners: map[string]ScannerInterface{
			".json":   &JSONScanner{},
			".ndjson": &JSONScanner{},
		},
	}
}

func (i *Ingestor) ProcessInput(path string, processFn func([]models.NetflowRecord)) error {
	extension := strings.ToLower(filepath.Ext(path))

	scanner, exists := i.scanners[extension]
	if !exists {
		return fmt.Errorf("unsupported file extension: %s", extension)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	return scanner.StreamRecords(file, processFn)
}
