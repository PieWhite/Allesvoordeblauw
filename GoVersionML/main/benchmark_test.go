package main

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkEndToEnd(b *testing.B) {
	// Find the provided test dataset
	testFile := "../benchmark.ndjson"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skipf("Test file %s not found in the current directory, skipping benchmark", testFile)
	}

	modelPath := filepath.Join("..", "Xgboost", "botnet_xgboost.json")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		b.Skipf("Model file %s not found, skipping benchmark", modelPath)
	}

	// Store original stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	// Redirect stdout/stderr to completely isolate performance testing focusing on CPU/RAM,
	// preventing terminal printing speed from skewing the results
	null, err := os.Open(os.DevNull)
	if err == nil {
		os.Stdout = null
		os.Stderr = null
		defer func() {
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			null.Close()
		}()
	}

	// Start timing only the actual execution
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Run with the test file, discarding normal output
		err := run([]string{testFile})
		if err != nil {
			b.Fatalf("run failed during benchmark: %v", err)
		}
	}
}
