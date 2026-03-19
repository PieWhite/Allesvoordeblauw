package config

import (
	"flag"
	"strings"
	"testing"
)

func TestAppConfig_ParseArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantNetflow string
		wantModel   string
		wantOutput  string
		wantErr     error // We use the specific error type for help checks
		wantErrStr  string
	}{
		{
			name:        "Valid: all flags and argument",
			args:        []string{"-m", "custom_model.json", "-o", "results.txt", "data.json"},
			wantNetflow: "data.json",
			wantModel:   "custom_model.json",
			wantOutput:  "results.txt",
			wantErr:     nil,
		},
		{
			name:        "Valid: defaults used",
			args:        []string{"input.json"},
			wantNetflow: "input.json",
			wantModel:   "./Xgboost/botnet_xgboost.json",
			wantOutput:  "",
			wantErr:     nil,
		},
		{
			name:       "Error: missing netflow file",
			args:       []string{"-m", "model.json"},
			wantErr:    nil, // err itself isn't nil, but we check wantErrStr
			wantErrStr: "you need to specify a netflow file",
		},
		{
			name:    "Error: help flag requested",
			args:    []string{"-h"},
			wantErr: flag.ErrHelp, // Specific error returned by FlagSet
		},
		{
			name:       "Error: empty arguments",
			args:       []string{},
			wantErrStr: "you need to specify a netflow file",
		},
		{
			name:       "Error: invalid flag provided",
			args:       []string{"-unknown", "val", "data.json"},
			wantErrStr: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AppConfig{}
			err := cfg.ParseArgs(tt.args)

			// 1. Handle the specific flag.ErrHelp case
			if tt.wantErr == flag.ErrHelp {
				if err != flag.ErrHelp {
					t.Errorf("Expected flag.ErrHelp, got %v", err)
				}
				return
			}

			// 2. Handle generic error string checks
			if tt.wantErrStr != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, got nil", tt.wantErrStr)
				}
				if !strings.Contains(err.Error(), tt.wantErrStr) {
					t.Errorf("Error %q does not contain %q", err.Error(), tt.wantErrStr)
				}
				return
			}

			// 3. Handle success cases
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if cfg.NetflowPath != tt.wantNetflow {
				t.Errorf("NetflowPath = %q, want %q", cfg.NetflowPath, tt.wantNetflow)
			}
			if cfg.ModelPath != tt.wantModel {
				t.Errorf("ModelPath = %q, want %q", cfg.ModelPath, tt.wantModel)
			}
			if cfg.OutputFile != tt.wantOutput {
				t.Errorf("OutputFile = %q, want %q", cfg.OutputFile, tt.wantOutput)
			}
		})
	}
}
