package ingest

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goversion/models"
)

type MockScanner struct {
	Called bool
	Err    error
}

func (m *MockScanner) StreamRecords(r io.Reader, fn func([]models.NetflowRecord)) error {
	m.Called = true
	return m.Err
}

func TestIngestor_ProcessInput(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Valid JSON Calls Scanner", func(t *testing.T) {
		mock := &MockScanner{}
		i := &Ingestor{
			scanners: map[string]ScannerInterface{
				".json": mock,
			},
		}
		path := filepath.Join(tmpDir, "test.json")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, func(r []models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Expected success, got err: %v", err)
		}
		if !mock.Called {
			t.Error("Ingestor did not delegate work to the Scanner interface")
		}
	})

	t.Run("Case Insensitivity Check", func(t *testing.T) {
		mock := &MockScanner{}
		i := &Ingestor{
			scanners: map[string]ScannerInterface{
				".json": mock,
			},
		}
		path := filepath.Join(tmpDir, "UPPER.JSON")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, func(r []models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Ingestor failed uppercase extension check: %v", err)
		}
	})

	t.Run("Unsupported Extension Returns Error", func(t *testing.T) {
		i := &Ingestor{
			scanners: map[string]ScannerInterface{
				".json": &MockScanner{},
			},
		}
		path := filepath.Join(tmpDir, "test.exe")
		os.WriteFile(path, []byte("binary data"), 0644)

		err := i.ProcessInput(path, nil)
		if err == nil {
			t.Error("Expected error for .exe, got nil")
		}
	})

	t.Run("File Not Found Error", func(t *testing.T) {
		i := &Ingestor{
			scanners: map[string]ScannerInterface{
				".json": &MockScanner{},
			},
		}
		err := i.ProcessInput("missing_file.json", nil)
		if err == nil || !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("Expected file open error, got: %v", err)
		}
	})
}

func TestJSONScanner_Bridge(t *testing.T) {
	s := &JSONScanner{}

	t.Run("Verify Execution Path", func(t *testing.T) {
		r := strings.NewReader(`{"first":"2024-01-01T00:00:00.000","last":"2024-01-01T00:00:01.000"}` + "\n")

		err := s.StreamRecords(r, func(record []models.NetflowRecord) {
		})

		if err != nil {
			t.Errorf("Bridge failed: scanner returned unexpected error: %v", err)
		}
	})
}
