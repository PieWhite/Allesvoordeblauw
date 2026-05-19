package pipeline

import (
	"os"
	"path/filepath"
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
			wantErr:   "pcap pipeline is not yet implemented",
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
			wantErr:   "pcap pipeline is not yet implemented",
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

			cfg := &config.AppConfig{
				InputPath: path,
				ModelPath: "nonexistent.json", // to force predictable AnalyzeFile failure
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
