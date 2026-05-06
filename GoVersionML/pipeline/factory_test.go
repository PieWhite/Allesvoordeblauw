package pipeline

import (
	"strings"
	"testing"

	"goversion/config"
)

func TestRunPipelineForInput(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		wantErr   string
	}{
		{
			name:      "Empty Extension",
			inputPath: "file_without_ext",
			wantErr:   "unsupported file extension:",
		},
		{
			name:      "Unsupported Extension",
			inputPath: "file.txt",
			wantErr:   "unsupported file extension: .txt",
		},
		{
			name:      "PCAP Extension",
			inputPath: "capture.pcap",
			wantErr:   "pcap pipeline is not yet implemented",
		},
		{
			name:      "JSON Extension with missing model",
			inputPath: "data.json",
			// AnalyzeFile will fail because the model doesn't exist
			wantErr: "failed loading xgboost model",
		},
		{
			name:      "NDJSON Extension with missing model",
			inputPath: "data.ndjson",
			wantErr:   "failed loading xgboost model",
		},
		{
			name:      "Uppercase PCAP Extension",
			inputPath: "CAPTURE.PCAP",
			wantErr:   "pcap pipeline is not yet implemented",
		},
		{
			name:      "Uppercase JSON Extension",
			inputPath: "DATA.JSON",
			wantErr:   "failed loading xgboost model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.AppConfig{
				InputPath: tt.inputPath,
				ModelPath: "nonexistent.json", // to force predictable AnalyzeFile failure
			}

			_, _, err := RunPipelineForInput(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
