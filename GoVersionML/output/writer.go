// Package output provides utilities for configuring and managing application output destinations,
// allowing simultaneous logging to standard output and optional file destinations.
package output

import (
	"fmt"
	"io"
	"os"
)

// Setup configures the application's output destination.
// It returns an io.Writer that writes to standard output, and optionally to a file
// if a non-empty outputFile path is provided. It also returns a cleanup function to close
// the file when done, and any error encountered during file creation.
func Setup(outputFile string) (io.Writer, func(), error) {
	if outputFile == "" {
		return os.Stdout, func() {}, nil
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file: %w", err)
	}

	writer := io.MultiWriter(os.Stdout, file)

	cleanup := func() {
		_ = file.Close()
	}

	return writer, cleanup, nil
}


