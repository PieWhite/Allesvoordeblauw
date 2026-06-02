package pipeline

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"goversion/config"
)

func TestRunPipelineForInput(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		filename  string
		wantErr   string
	}{
		{
			name:      "Empty Extension",
			filename:  "file_without_ext",
			wantErr:   "unsupported file extension:",
		},
		{
			name:      "Unsupported Extension",
			filename:  "file.txt",
			wantErr:   "unsupported file extension: .txt",
		},
		{
			name:      "PCAP Extension",
			filename:  "capture.pcap",
			wantErr:   "failed loading xgboost model",
		},
		{
			name:      "JSON Extension with missing model",
			filename:  "data.json",
			wantErr:   "failed loading xgboost model",
		},
		{
			name:      "NDJSON Extension with missing model",
			filename:  "data.ndjson",
			wantErr:   "failed loading xgboost model",
		},
		{
			name:      "Uppercase PCAP Extension",
			filename:  "CAPTURE.PCAP",
			wantErr:   "failed loading xgboost model",
		},
		{
			name:      "Uppercase JSON Extension",
			filename:  "DATA.JSON",
			wantErr:   "failed loading xgboost model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tempDir, tt.filename)
			f, err := os.Create(path)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			f.Close()

			originalNetflow := NetflowModelPath
			originalPcap := PcapModelPath
			NetflowModelPath = "nonexistent.json"
			PcapModelPath = "nonexistent.json"
			t.Cleanup(func() {
				NetflowModelPath = originalNetflow
				PcapModelPath = originalPcap
			})

			cfg := &config.AppConfig{
				InputPath: path,
			}

			_, _, err = RunPipelineForInput(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestClassifyDirectory(t *testing.T) {
	tempDir := t.TempDir()
	createTestFile := func(rel string) string {
		full := filepath.Join(tempDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("failed to create parent directory: %v", err)
		}
		if err := os.WriteFile(full, []byte("{}"), 0o644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		return full
	}

	jsonFile := createTestFile("a.json")
	ndjsonFile := createTestFile("b.ndjson")
	unsupportedFile := createTestFile("nested/c.txt")

	got, err := classifyDirectory(tempDir)
	if err != nil {
		t.Fatalf("classifyDirectory returned error: %v", err)
	}

	if len(got.json) != 1 || !slices.Contains(got.json, jsonFile) {
		t.Fatalf("expected json files to contain %q, got %v", jsonFile, got.json)
	}
	if len(got.ndjson) != 1 || !slices.Contains(got.ndjson, ndjsonFile) {
		t.Fatalf("expected ndjson files to contain %q, got %v", ndjsonFile, got.ndjson)
	}
	if len(got.unsupported) != 1 || !slices.Contains(got.unsupported, unsupportedFile) {
		t.Fatalf("expected unsupported files to contain %q, got %v", unsupportedFile, got.unsupported)
	}
}

func TestConfirmDirectoryParseMixedFlow(t *testing.T) {
	originalStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = originalStdin })

	mockStdinWithInput := func(t *testing.T, input string) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create stdin pipe: %v", err)
		}
		if _, err := w.WriteString(input); err != nil {
			t.Fatalf("failed to write stdin input: %v", err)
		}
		w.Close()
		os.Stdin = r
		t.Cleanup(func() { r.Close() })
	}

	cf := classifiedFiles{
		json:   []string{"a.json"},
		ndjson: []string{"b.ndjson"},
	}

	t.Run("AcceptMixedTypes", func(t *testing.T) {
		mockStdinWithInput(t, "yes\n")
		if err := confirmDirectoryParse(cf); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("RejectMixedTypes", func(t *testing.T) {
		mockStdinWithInput(t, "n\n")
		err := confirmDirectoryParse(cf)
		if err == nil {
			t.Fatal("expected cancellation error, got nil")
		}
		if !strings.Contains(err.Error(), "parsing cancelled by user") {
			t.Fatalf("expected cancellation error, got %v", err)
		}
	})

	t.Run("AcceptCSVOnly", func(t *testing.T) {
		mockStdinWithInput(t, "yes\n")
		cfCSV := classifiedFiles{
			csv: []string{"a.csv"},
		}
		if err := confirmDirectoryParse(cfCSV); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}

func TestProcessBatchErrorHandling(t *testing.T) {
	cf := classifiedFiles{
		json: []string{"a.json"},
	}

	originalNetflow := NetflowModelPath
	NetflowModelPath = "missing-model.json"
	t.Cleanup(func() {
		NetflowModelPath = originalNetflow
	})

	_, _, err := processBatch(&config.AppConfig{}, cf, 1)
	if err == nil {
		t.Fatal("expected model loading error, got nil")
	}
	if !strings.Contains(err.Error(), "failed loading xgboost model") {
		t.Fatalf("expected wrapped model load error, got %v", err)
	}
}

func TestProcessBatchCSVErrorHandling(t *testing.T) {
	cf := classifiedFiles{
		csv: []string{"a.csv"},
	}

	originalNetflow := NetflowModelPath
	NetflowModelPath = "missing-model.json"
	t.Cleanup(func() {
		NetflowModelPath = originalNetflow
	})

	_, _, err := processBatch(&config.AppConfig{}, cf, 1)
	if err == nil {
		t.Fatal("expected model loading error, got nil")
	}
	if !strings.Contains(err.Error(), "failed loading xgboost model for Netflow") {
		t.Fatalf("expected wrapped Netflow model load error, got %v", err)
	}
}

func TestResolveModelPath(t *testing.T) {
	t.Run("Netflow Resolution", func(t *testing.T) {
		got := resolveModelPath(false)
		wantStr := "botnet_xgboost.json"
		if !strings.Contains(got, wantStr) {
			t.Errorf("resolveModelPath(false) = %q, expected it to contain %q", got, wantStr)
		}
	})

	t.Run("PCAP Resolution", func(t *testing.T) {
		got := resolveModelPath(true)
		wantStr := "pcap_xgboost.json"
		if !strings.Contains(got, wantStr) {
			t.Errorf("resolveModelPath(true) = %q, expected it to contain %q", got, wantStr)
		}
	})
}
