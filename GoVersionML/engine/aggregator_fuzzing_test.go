package engine

import (
	"goversion/models"
	"testing"
)

// FuzzAggregator provides high-entropy inputs to the aggregation engine
func FuzzAggregator(f *testing.F) {
	// Seed with a "Healthy" record
	f.Add("192.168.1.1", "8.8.8.8", "2026-03-17T11:08:00.000", "2026-03-17T11:08:00.500", "S", 443, int64(1024), int64(10))
	// Seed with "Broken" data
	f.Add("", "", "invalid", "invalid", "", 0, int64(0), int64(0))

	f.Fuzz(func(t *testing.T, src, dst, first, last, flags string, port int, bytes, packets int64) {
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
			Proto:     6, // Fuzzing 6, 17, 1 or random values here is also an option
		}

		// Update should be panic-free regardless of input
		a.Update(record)

		// Verification loop
		for _, stats := range a.AllIPStats() {
			vec := stats.ToMLVector()

			if len(vec) != 36 {
				t.Errorf("Vector size mismatch: %d", len(vec))
			}

			for i, val := range vec {
				// Detect NaN/Inf which would break XGBoost
				if isInvalidFloat(val) {
					t.Errorf("Non-finite float at index %d: %v", i, val)
				}
			}
		}
	})
}

func isInvalidFloat(f float64) bool {
	// A float is invalid if it is NaN or Infinite
	return (f != f) || (f > 1e308) || (f < -1e308)
}
