package output

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSetup(t *testing.T) {
	t.Run("Console only (no output file)", func(t *testing.T) {
		// When outputFile is empty
		writer, cleanup, err := Setup("")

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if writer == nil {
			t.Error("Expected a writer, got nil")
		}

		// Cleanup should not crash
		cleanup()
	})

	t.Run("Console and File", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "test_output.txt")

		writer, cleanup, err := Setup(outPath)
		if err != nil {
			t.Fatalf("Failed to setup output: %v", err)
		}

		// Test writing
		message := "hello world"
		_, err = io.WriteString(writer, message)
		if err != nil {
			t.Fatalf("Failed to write to multiwriter: %v", err)
		}

		// Must call cleanup to close the file handle
		cleanup()

		// Verify the file was actually created and contains the message
		content, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("Could not read back the output file: %v", err)
		}
		if string(content) != message {
			t.Errorf("Expected file content %q, got %q", message, string(content))
		}
	})

	t.Run("Invalid File Path", func(t *testing.T) {
		// Attempting to create a file in a non-existent directory
		_, _, err := Setup("/non/existent/path/to/file.txt")

		if err == nil {
			t.Error("Expected error for invalid path, got nil")
		}
	})
}
