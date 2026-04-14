package ingest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goversion/models"
	"goversion/scanner"
	"goversion/NetflowScanner"
)

type ScannerInterface interface {
	StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error
}

type JSONScanner struct{}

// type PCAPScanner struct{}

func (js *JSONScanner) StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error {
	return scanner.StreamNetflow(r, fn)
}

type NetflowScanner struct{}

func (ns *NetflowScanner) StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error {
	return netflowscanner.StreamNetflowText(r, fn)
}

// func (ps *PCAPScanner) StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error {
// 	return scanner.StreamPCAP(r, fn)
// }

type Ingestor struct {
	scanners map[string]ScannerInterface
}

func NewIngestor() *Ingestor {
	return &Ingestor{
		scanners: map[string]ScannerInterface{
			".json":    &JSONScanner{},
			".netflow": &NetflowScanner{},
			//".pcap": &PCAPScanner{},
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
