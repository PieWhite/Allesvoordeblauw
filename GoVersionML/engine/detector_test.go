package engine

import (
	"math"
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

func TestNewDetector_MockInitialization(t *testing.T) {
	t.Run("Invalid Path Error", func(t *testing.T) {
		d, err := NewDetector("invalid/path/to/model.json")
		if err == nil {
			t.Error("Expected error for invalid model path, got nil")
		}
		if d != nil {
			t.Error("Detector should be nil on error")
		}
	})
}

func TestEvaluateBatch(t *testing.T) {
	d := &Detector{
		model: &FastXGBoost{
			Trees: []FastTree{
				{FastNode{IsLeaf: true, LeafValue: 0.84729786}}, // sigmoid(0.84729786) = 0.7
			},
		},
		maxProbs:    make(map[uint32]float64),
		maxFeatures: make(map[uint32][]float64),
	}

	stats := NewIPStats()
	ipVal, _ := ParseIPv4("1.2.3.4")
	stats.IP = ipVal
	stats.FlowCount = 2

	d.evaluateBatch([]*IPStats{stats})

	expected := 0.7
	prob := d.maxProbs[ipVal]
	t.Logf("ipVal: %d, d.maxProbs: %+v", ipVal, d.maxProbs)
	if math.Abs(prob-expected) > 1e-6 {
		t.Errorf("Expected prob ~%v, got %v", expected, prob)
	}
}

func TestDetector_ProcessRecord(t *testing.T) {
	d := &Detector{
		windowManager: NewNetflowWindowManager(WindowFlushPolicy{Mode: WindowFlushAssumeOrdered}),
	}
	rec := models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"}

	d.ProcessRecord(rec)

	if d.TotalCount() != 1 {
		t.Errorf("TotalRecords not incremented: got %d", d.TotalCount())
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

func TestDetector_TotalCount(t *testing.T) {
	d := &Detector{}
	d.TotalRecords = 42
	if d.TotalCount() != 42 {
		t.Errorf("Expected 42, got %d", d.TotalCount())
	}
}

func TestDetector_ProcessRecords(t *testing.T) {
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
