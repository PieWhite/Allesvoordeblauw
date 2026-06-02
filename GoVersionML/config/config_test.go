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
		wantOutput  string
		wantSubnet  string
		wantErr     error // We use the specific error type for help checks
		wantErrStr  string
	}{
		{
			name:        "Valid: all flags and argument",
			args:        []string{"-o", "results.txt", "data.json"},
			wantNetflow: "data.json",
			wantOutput:  "results.txt",
			wantErr:     nil,
		},
		{
			name:        "Valid: defaults used",
			args:        []string{"input.json"},
			wantNetflow: "input.json",
			wantOutput:  "",
			wantErr:     nil,
		},
		{
			name:        "Valid: subnet flag",
			args:        []string{"-subnet", "192.251.x.x", "data.json"},
			wantNetflow: "data.json",
			wantSubnet:  "192.251.x.x",
			wantErr:     nil,
		},
		{
			name:       "Error: missing netflow file",
			args:       []string{"-o", "results.txt"},
			wantErrStr: "you need to specify an input file",
		},
		{
			name:    "Error: help flag requested",
			args:    []string{"-h"},
			wantErr: flag.ErrHelp, // Specific error returned by FlagSet
		},
		{
			name:       "Error: empty arguments",
			args:       []string{},
			wantErrStr: "you need to specify an input file",
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

			if cfg.InputPath != tt.wantNetflow {
				t.Errorf("InputPath = %q, want %q", cfg.InputPath, tt.wantNetflow)
			}
			if cfg.OutputFile != tt.wantOutput {
				t.Errorf("OutputFile = %q, want %q", cfg.OutputFile, tt.wantOutput)
			}
			if cfg.Subnet != tt.wantSubnet {
				t.Errorf("Subnet = %q, want %q", cfg.Subnet, tt.wantSubnet)
			}
		})
	}
}

func TestMatchSubnet(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		subnet    string
		wantMatch bool
	}{
		{
			name:      "Empty subnet matches anything",
			ip:        "192.168.1.1",
			subnet:    "",
			wantMatch: true,
		},
		{
			name:      "CIDR match - exact subnet",
			ip:        "192.168.1.50",
			subnet:    "192.168.1.0/24",
			wantMatch: true,
		},
		{
			name:      "CIDR match - outside subnet",
			ip:        "192.168.2.50",
			subnet:    "192.168.1.0/24",
			wantMatch: false,
		},
		{
			name:      "CIDR match - large subnet",
			ip:        "192.251.71.47",
			subnet:    "192.251.0.0/16",
			wantMatch: true,
		},
		{
			name:      "Wildcard matching x.x",
			ip:        "192.251.85.44",
			subnet:    "192.251.x.x",
			wantMatch: true,
		},
		{
			name:      "Wildcard matching asterisk",
			ip:        "192.251.85.44",
			subnet:    "192.251.*.*",
			wantMatch: true,
		},
		{
			name:      "Prefix matching",
			ip:        "196.251.87.62",
			subnet:    "196.251",
			wantMatch: true,
		},
		{
			name:      "Prefix matching trailing dot",
			ip:        "196.251.87.62",
			subnet:    "196.251.",
			wantMatch: true,
		},
		{
			name:      "Mismatch",
			ip:        "192.168.1.1",
			subnet:    "10.0.0.x",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchSubnet(tt.ip, tt.subnet)
			if got != tt.wantMatch {
				t.Errorf("MatchSubnet(%q, %q) = %v, want %v", tt.ip, tt.subnet, got, tt.wantMatch)
			}
		})
	}
}

