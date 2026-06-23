// hll.go implements a HyperLogLog cardinality estimator for counting unique
// uint32 values (such as IP addresses) with ~0.81% standard error using only
// 16KB of memory at precision 14.
package engine

import (
	"math"
)

type HyperLogLog struct {
	m   int
	reg []uint8
}

func NewHyperLogLog(precision uint8) *HyperLogLog {
	m := 1 << precision
	return &HyperLogLog{
		m:   m,
		reg: make([]uint8, m),
	}
}

func hashUint32(key uint32) uint32 {
	key ^= key >> 16
	key *= 0x85ebca6b
	key ^= key >> 13
	key *= 0xc2b2ae35
	key ^= key >> 16
	return key
}

func (h *HyperLogLog) Add(val uint32) {
	hash := hashUint32(val)

	idx := hash >> (32 - 14)

	w := hash << 14
	r := 1
	for (w&0x80000000) == 0 && r <= 18 {
		r++
		w <<= 1
	}
	if uint8(r) > h.reg[idx] {
		h.reg[idx] = uint8(r)
	}
}

func (h *HyperLogLog) Estimate() int {
	sum := 0.0
	for _, val := range h.reg {
		sum += 1.0 / math.Pow(2.0, float64(val))
	}

	alpha := 0.7213 / (1.0 + 1.079/float64(h.m))
	est := alpha * float64(h.m) * float64(h.m) / sum

	if est <= 2.5*float64(h.m) {
		v := 0
		for _, val := range h.reg {
			if val == 0 {
				v++
			}
		}
		if v > 0 {
			est = float64(h.m) * math.Log(float64(h.m)/float64(v))
		}
	}
	return int(est)
}

func (h *HyperLogLog) Merge(other *HyperLogLog) {
	if other == nil || len(h.reg) != len(other.reg) {
		return
	}
	for i := 0; i < len(h.reg); i++ {
		if other.reg[i] > h.reg[i] {
			h.reg[i] = other.reg[i]
		}
	}
}
