package ingest

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goversion/models"
)

// --- MOCK SECTION ---
// MockScanner implements the Scanner interface for unit testing Ingestor logic.

type MockScanner struct {
	Called bool
	Err    error
}

func (m *MockScanner) StreamNetflow(r io.Reader, fn func([]models.NetflowRecord)) error {
	m.Called = true
	return m.Err
}

// --- UNIT TESTS ---
// These tests verify that Ingestor handles files and routing correctly.

func TestIngestor_ProcessInput(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Valid JSON Calls Scanner", func(t *testing.T) {
		mock := &MockScanner{}
		i := &Ingestor{NetflowScanner: mock}
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
		i := &Ingestor{NetflowScanner: mock}
		path := filepath.Join(tmpDir, "UPPER.JSON")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, func(r []models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Ingestor failed uppercase extension check: %v", err)
		}
	})

	t.Run("Unsupported Extension Returns Error", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: &MockScanner{}}
		path := filepath.Join(tmpDir, "test.exe")
		os.WriteFile(path, []byte("binary data"), 0644)

		err := i.ProcessInput(path, nil)
		if err == nil {
			t.Error("Expected error for .exe, got nil")
		}
	})

	t.Run("File Not Found Error", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: &MockScanner{}}
		err := i.ProcessInput("missing_file.json", nil)
		if err == nil || !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("Expected file open error, got: %v", err)
		}
	})

	t.Run("Scanner Not Initialized", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: nil}
		path := filepath.Join(tmpDir, "nil_test.json")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, nil)
		if err == nil || err.Error() != "scanner not initialized" {
			t.Errorf("Expected nil-scanner error, got: %v", err)
		}
	})
}

func TestJSONScanner_Bridge(t *testing.T) {
	s := &JSONScanner{}

	t.Run("Verify Execution Path", func(t *testing.T) {
		r := strings.NewReader(`[]`)

		err := s.StreamNetflow(r, func(record []models.NetflowRecord) {
		})

		if err != nil {
			t.Errorf("Bridge failed: scanner returned unexpected error: %v", err)
		}
	})
}
