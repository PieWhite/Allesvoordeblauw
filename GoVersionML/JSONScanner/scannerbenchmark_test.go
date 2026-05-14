package JSONScanner

import (
	"bytes"
	"strings"
	"testing"

	"goversion/models"
)

// Helper function to create a big chunk of dummy JSON data
func generateMockJSON(numRecords int) []byte {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < numRecords; i++ {
		// Replace this with fields that actually match your models.NetflowRecord
		sb.WriteString(`{"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "bytes": 512}`)
		if i < numRecords-1 {
			sb.WriteString(",\n")
		}
	}
	sb.WriteString("]")
	return []byte(sb.String())
}

// Benchmarks in Go must start with the word "Benchmark" and take *testing.B
func BenchmarkStreamNetflow(b *testing.B) {
	// 1. Setup phase: Generate 10,000 records
	mockData := generateMockJSON(10000)

	// 2. Crucial: Reset the timer!
	// We don't want the time it took to generate the mock data to ruin our benchmark scores.
	b.ResetTimer()

	// 3. The Benchmark Loop
	// b.N is dynamically adjusted by Go to run the loop enough times to get a reliable average.
	for i := 0; i < b.N; i++ {
		// Create a fresh reader for this iteration
		reader := bytes.NewReader(mockData)

		// Run the function
		err := StreamNetflow(reader, func(records []models.NetflowRecord) {
			// Blackhole the result (do nothing). We just want to measure the parsing overhead.
		})

		if err != nil {
			b.Fatalf("Benchmark failed with error: %v", err)
		}
	}
}
