// aggregator_fuzzing_test.go provides fuzz testing for the aggregation engine,
// ensuring panic-free operation and finite ML vector output under arbitrary input.
package engine

import (
	"math"
	"testing"

	"goversion/models"
)

func FuzzAggregator(f *testing.F) {
	f.Add("192.168.1.1", "8.8.8.8", "2026-03-17T11:08:00.000", "2026-03-17T11:08:00.500", "S", 443, int64(1024), int64(10), 6)
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

		a.Update(record)

		for _, stats := range a.AllIPStats() {
			vec := stats.ToMLVector()

			if len(vec) != 21 {
				t.Errorf("Vector size mismatch: %d", len(vec))
			}

			for i, val := range vec {
				if math.IsNaN(val) || math.IsInf(val, 0) {
					t.Errorf("Non-finite float at index %d: %v", i, val)
				}
			}
		}
	})
}
