package engine

import (
	"math"
	"testing"

	"goversion/models"
)

// FuzzAggregator provides high-entropy inputs to the aggregation engine
func FuzzAggregator(f *testing.F) {
	// Seed with a "Healthy" record
	f.Add("192.168.1.1", "8.8.8.8", "2026-03-17T11:08:00.000", "2026-03-17T11:08:00.500", "S", 443, int64(1024), int64(10), 6)
	// Seed with "Broken" data
	f.Add("", "", "invalid", "invalid", "", 0, int64(0), int64(0), 0)

	f.Fuzz(func(t *testing.T, src, dst, first, last, flags string, port int, bytes, packets int64, proto int) {
		a := NewAggregator()

		record := models.NetflowRecord{
			Src4Addr:  src,
			Dst4Addr:  dst,
			First:     first,
			Last:      last,
			TCPFlags:  flags,
			DstPort:   port,
			InBytes:   bytes,
			InPackets: packets,
			Proto:     proto,
		}

		// Update should be panic-free regardless of input
		a.Update(record)

		// Verification loop
		for _, stats := range a.AllIPStats() {
			vec := stats.ToMLVector()

			if len(vec) != 21 {
				t.Errorf("Vector size mismatch: %d", len(vec))
			}

			for i, val := range vec {
				// Detect NaN/Inf which would break XGBoost
				if math.IsNaN(val) || math.IsInf(val, 0) {
					t.Errorf("Non-finite float at index %d: %v", i, val)
				}
			}
		}
	})
}
