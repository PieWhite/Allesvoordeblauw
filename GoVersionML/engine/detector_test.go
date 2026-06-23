// detector_test.go verifies detector lifecycle, initialization, and
// single-record processing.
package engine

import (
	"testing"

	"goversion/models"
)

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

func TestDetector_TotalCount(t *testing.T) {
	d := &Detector{}
	d.TotalRecords = 42
	if d.TotalCount() != 42 {
		t.Errorf("Expected 42, got %d", d.TotalCount())
	}
}
