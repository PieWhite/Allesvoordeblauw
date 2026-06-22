// Package output contains unit tests for the output package, ensuring correct behavior
// of the writer setup for console and file targets under normal and failure conditions.
package output

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestSetup validates output destination configuration for console, file-bound,
// and invalid outputs.
func TestSetup(t *testing.T) {
	tests := []struct {
		name        string
		outputFile  func(t *testing.T) string
		wantWrite   bool
		wantContent string
		wantErr     bool
	}{
		{
			name: "Console only (no output file)",
			outputFile: func(t *testing.T) string {
				return ""
			},
			wantWrite: false,
			wantErr:   false,
		},
		{
			name: "Console and valid file",
			outputFile: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "test_output.txt")
			},
			wantWrite:   true,
			wantContent: "hello pencilgon",
			wantErr:     false,
		},
		{
			name: "Invalid file path",
			outputFile: func(t *testing.T) string {
				return "/non/existent/directory/path/to/file.txt"
			},
			wantWrite: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.outputFile(t)
			w, cleanup, err := Setup(path)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Setup(%q) unexpected error status: got error = %v, wantErr = %v", path, err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if w == nil {
				t.Error("Setup() returned a nil writer, expected non-nil")
			}

			if tt.wantWrite {
				_, err = io.WriteString(w, tt.wantContent)
				if err != nil {
					t.Fatalf("Failed to write to configured writer: %v", err)
				}
			}

			if cleanup == nil {
				t.Fatal("Setup() returned a nil cleanup function, expected non-nil")
			}
			cleanup()

			if tt.wantWrite {
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("Failed to read back output file: %v", err)
				}
				if string(content) != tt.wantContent {
					t.Errorf("File content mismatch: got %q, want %q", string(content), tt.wantContent)
				}
			}
		})
	}
}

