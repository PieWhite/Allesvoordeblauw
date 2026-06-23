/*
Package main contains performance benchmarks for parsing and processing netflow records.
Run benchmarks using the powershell script or manually:
  go test ./main -bench=BenchmarkEndToEnd -run=^$ -benchmem -count=6
*/
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkEndToEnd(b *testing.B) {
	testFile := "../benchmark.ndjson"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skipf("Test file %s not found in current directory, skipping benchmark", testFile)
	}

	modelPath := filepath.Join("..", "Xgboost", "botnet_xgboost.json")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		b.Skipf("Model file %s not found, skipping benchmark", modelPath)
	}

	oldStdout := os.Stdout
	oldStderr := os.Stderr

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

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := run([]string{testFile})
		if err != nil {
			b.Fatalf("run failed during benchmark: %v", err)
		}
	}
}
