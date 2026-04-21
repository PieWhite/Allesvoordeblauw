package ingest

import (
	"io"

	"goversion/models"
	"goversion/scanner"
)

type NetflowScanner struct{}

func (s *NetflowScanner) StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error {
	return scanner.StreamNetflow(r, fn)
}

func init() {
	Register(".json", &NetflowScanner{})
	Register(".ndjson", &NetflowScanner{})
}
