package engine

import (
	"math"
	"testing"
)

func TestHyperLogLog(t *testing.T) {
	h := NewHyperLogLog(14)

	// Add 10,000 unique values
	for i := uint32(0); i < 10000; i++ {
		h.Add(i)
	}

	est := h.Estimate()
	expected := 10000.0
	diff := math.Abs(float64(est) - expected)
	pctError := (diff / expected) * 100.0

	t.Logf("True count: 10000, Estimate: %d, Error: %.2f%%", est, pctError)

	// Check if error is within HLL standard error bound (2.0%)
	if pctError > 2.0 {
		t.Errorf("Expected HLL estimate to be within 2.0%% error bound, got %.2f%% error (estimate: %d)", pctError, est)
	}
}

func TestHyperLogLog_Empty(t *testing.T) {
	h := NewHyperLogLog(14)
	est := h.Estimate()
	if est != 0 {
		t.Errorf("Expected estimate for empty HLL to be 0, got %d", est)
	}
}
