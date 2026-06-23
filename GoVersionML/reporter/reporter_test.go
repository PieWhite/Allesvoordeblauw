// Package reporter contains unit tests for the reporter package, validating ML summary
// printing formatting, sorting, and boundaries.
package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"goversion/models"
)

// TestPrintSummary verifies output layout, record filtering, sorting, explanation inclusion,
// and statistics rendering in the summary report.
func TestPrintSummary(t *testing.T) {
	tests := []struct {
		name           string
		results        []models.MLResult
		totalUniqueIPs int
		totalRecords   int64
		duration       time.Duration
		verify         func(t *testing.T, output string)
	}{
		{
			name: "Standard results with botnets and multiple benign hosts",
			results: []models.MLResult{
				{IP: "1.1.1.1", Probability: 99.9, IsBotnet: true},
				{IP: "2.2.2.2", Probability: 85.0, IsBotnet: true},
				{IP: "3.3.3.3", Probability: 10.0, IsBotnet: false},
				{IP: "4.4.4.4", Probability: 15.0, IsBotnet: false},
				{IP: "5.5.5.5", Probability: 5.0, IsBotnet: false},
				{IP: "6.6.6.6", Probability: 2.0, IsBotnet: false},
				{IP: "7.7.7.7", Probability: 1.0, IsBotnet: false},
				{IP: "8.8.8.8", Probability: 0.5, IsBotnet: false},
			},
			totalUniqueIPs: 8,
			totalRecords:   1000,
			duration:       2 * time.Second,
			verify: func(t *testing.T, output string) {
				if !strings.Contains(output, "[BOTNET DETECTED] IP: 1.1.1.1") {
					t.Errorf("High probability botnet 1.1.1.1 missing from output")
				}
				if count := strings.Count(output, "[BOTNET DETECTED]"); count != 2 {
					t.Errorf("Expected 2 botnet detections, got %d", count)
				}
				if count := strings.Count(output, "[BENIGN TRAFFIC ]"); count != 5 {
					t.Errorf("Expected exactly 5 benign traffic logs, got %d", count)
				}
				if strings.Contains(output, "8.8.8.8") {
					t.Error("Top-5 limit failed: lowest probability benign host 8.8.8.8 was printed")
				}
				idx4 := strings.Index(output, "4.4.4.4")
				idx3 := strings.Index(output, "3.3.3.3")
				if idx4 > idx3 {
					t.Error("Benign hosts were not sorted by probability in descending order")
				}
				if !strings.Contains(output, "Processed 1000 records.") {
					t.Error("Total records summary count missing or incorrect")
				}
				if !strings.Contains(output, "Execution time: 2.0000 seconds") {
					t.Error("Execution time formatting is incorrect")
				}
			},
		},
		{
			name: "Filtering empty IPs",
			results: []models.MLResult{
				{IP: "", Probability: 90.0, IsBotnet: true},
				{IP: "1.1.1.1", Probability: 80.0, IsBotnet: true},
			},
			totalUniqueIPs: 1,
			totalRecords:   100,
			duration:       500 * time.Millisecond,
			verify: func(t *testing.T, output string) {
				if strings.Contains(output, "ML Probability: 90.00%") {
					t.Error("Results with empty IP should be filtered out")
				}
				if !strings.Contains(output, "1.1.1.1") {
					t.Error("Expected result with valid IP to be printed")
				}
			},
		},
		{
			name: "No botnets detected",
			results: []models.MLResult{
				{IP: "2.2.2.2", Probability: 5.0, IsBotnet: false},
			},
			totalUniqueIPs: 1,
			totalRecords:   50,
			duration:       100 * time.Millisecond,
			verify: func(t *testing.T, output string) {
				if strings.Contains(output, "[BOTNET DETECTED]") {
					t.Error("Expected no botnet logs to be printed")
				}
				if !strings.Contains(output, "[BENIGN TRAFFIC ] IP: 2.2.2.2") {
					t.Error("Expected benign host to be printed")
				}
			},
		},
		{
			name: "Botnet with explanation",
			results: []models.MLResult{
				{IP: "1.1.1.1", Probability: 99.0, IsBotnet: true, Explanation: "Mirai heuristics"},
			},
			totalUniqueIPs: 1,
			totalRecords:   10,
			duration:       time.Second,
			verify: func(t *testing.T, output string) {
				expected := "[BOTNET DETECTED] IP: 1.1.1.1         | ML Probability:  99.00% (Mirai heuristics)\n"
				if !strings.Contains(output, expected) {
					t.Errorf("Explanation format incorrect, got output: %q", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			PrintSummary(&buf, tt.results, tt.totalUniqueIPs, tt.totalRecords, tt.duration)
			tt.verify(t, buf.String())
		})
	}
}

