// detector_results_test.go verifies result extraction, formatting, and
// threshold-based classification of detection probabilities.
package engine

import (
	"testing"

	"goversion/models"
)

func TestDetector_CalculateResults_Empty(t *testing.T) {
	d := &Detector{
		windowManager: NewNetflowWindowManager(WindowFlushPolicy{Mode: WindowFlushAssumeOrdered}),
		model:         &FastXGBoost{},
	}

	results, _ := d.CalculateResults()

	if results == nil {
		t.Fatal("Expected an empty slice, got nil")
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty aggregator, got %d", len(results))
	}
}

func TestDetector_FormatResults_Threshold(t *testing.T) {
	d := &Detector{}
	ipBot, _ := ParseIPv4("1.1.1.1")
	ipBenign, _ := ParseIPv4("2.2.2.2")
	probs := map[uint32]float64{
		ipBot:    0.81,
		ipBenign: 0.49,
	}

	results := d.formatResults(probs)
	for _, res := range results {
		if res.IP == "1.1.1.1" && !res.IsBotnet {
			t.Error("0.81 should be marked as botnet")
		}
		if res.IP == "2.2.2.2" && res.IsBotnet {
			t.Error("0.49 should not be marked as botnet")
		}
	}
}

func TestDetector_ProcessRecords_CountsAll(t *testing.T) {
	d := &Detector{
		windowManager: NewNetflowWindowManager(WindowFlushPolicy{Mode: WindowFlushAssumeOrdered}),
	}
	records := []models.NetflowRecord{
		{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"},
		{Src4Addr: "2.2.2.2", First: "2026-03-17T12:05:00.000", Last: "2026-03-17T12:05:00.000"},
		{Src4Addr: "3.3.3.3", First: "invalid-time-stamp"},
	}
	d.ProcessRecords(records)

	if d.TotalCount() != 3 {
		t.Errorf("Expected 3, got %d", d.TotalCount())
	}
}
