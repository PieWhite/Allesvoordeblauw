package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"goversion/models"
)

func TestPrintSummary(t *testing.T) {
	// 1. Setup sample data
	results := []models.MLResult{
		{IP: "1.1.1.1", Probability: 99.9, IsBotnet: true},
		{IP: "2.2.2.2", Probability: 85.0, IsBotnet: true},
		{IP: "3.3.3.3", Probability: 10.0, IsBotnet: false},
		{IP: "4.4.4.4", Probability: 15.0, IsBotnet: false},
		{IP: "5.5.5.5", Probability: 5.0, IsBotnet: false},
		{IP: "6.6.6.6", Probability: 2.0, IsBotnet: false},
		{IP: "7.7.7.7", Probability: 1.0, IsBotnet: false},
		{IP: "8.8.8.8", Probability: 0.5, IsBotnet: false}, // This should not be printed (top 5 only)
	}

	// 2. Use a Buffer to capture output instead of os.Stdout
	var buf bytes.Buffer
	totalRecords := int64(1000)
	duration := 2 * time.Second

	PrintSummary(&buf, results, len(results), totalRecords, duration)
	output := buf.String()

	// 3. Assertions
	t.Run("Check Botnet Detection", func(t *testing.T) {
		if !strings.Contains(output, "[BOTNET DETECTED] IP: 1.1.1.1") {
			t.Errorf("High probability botnet missing from output")
		}
		if strings.Count(output, "[BOTNET DETECTED]") != 2 {
			t.Errorf("Expected 2 botnet detections, found %d", strings.Count(output, "[BOTNET DETECTED]"))
		}
	})

	t.Run("Check Benign Limit (Top 5)", func(t *testing.T) {
		// We expect exactly 5 benign entries
		count := strings.Count(output, "[BENIGN TRAFFIC ]")
		if count != 5 {
			t.Errorf("Expected 5 benign entries, got %d", count)
		}
		// 8.8.8.8 was the 6th benign, it should be absent
		if strings.Contains(output, "8.8.8.8") {
			t.Error("Reporter printed more than 5 benign entries")
		}
	})

	t.Run("Check Sorting", func(t *testing.T) {
		// Since we sorted by probability, 4.4.4.4 (15%) should appear before 3.3.3.3 (10%)
		idx4 := strings.Index(output, "4.4.4.4")
		idx3 := strings.Index(output, "3.3.3.3")
		if idx4 > idx3 {
			t.Error("Benign traffic was not sorted by probability correctly")
		}
	})

	t.Run("Check Summary Totals", func(t *testing.T) {
		if !strings.Contains(output, "Processed 1000 records") {
			t.Error("Total records count incorrect")
		}
		if !strings.Contains(output, "Execution time: 2.0000 seconds") {
			t.Errorf("Duration formatting incorrect: %s", output)
		}
	})
}
