package engine

import (
	"math"
)

// HyperLogLog implements an extremely memory-efficient unique element cardinality estimator.
type HyperLogLog struct {
	m   int
	reg []uint8
}

// NewHyperLogLog creates a new estimator with 2^precision registers.
// Precision 14 (16384 registers) gives a standard error of ~0.81% and uses 16KB of memory.
func NewHyperLogLog(precision uint8) *HyperLogLog {
	m := 1 << precision
	return &HyperLogLog{
		m:   m,
		reg: make([]uint8, m),
	}
}

// hashUint32 uses MurmurHash3's 32-bit finalizer mix function for excellent avalanche properties.
func hashUint32(key uint32) uint32 {
	key ^= key >> 16
	key *= 0x85ebca6b
	key ^= key >> 13
	key *= 0xc2b2ae35
	key ^= key >> 16
	return key
}

// Add adds a uint32 value (like an IP) to the estimator.
func (h *HyperLogLog) Add(val uint32) {
	hash := hashUint32(val)

	// Use top bits for register index (precision = 14)
	idx := hash >> (32 - 14)

	// w is the remaining bits (32 - 14 = 18 bits)
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

// Estimate returns the estimated cardinality.
func (h *HyperLogLog) Estimate() int {
	sum := 0.0
	for _, val := range h.reg {
		sum += 1.0 / math.Pow(2.0, float64(val))
	}

	// Constant alpha for m = 16384 (precision = 14)
	alpha := 0.7213 / (1.0 + 1.079/float64(h.m))
	est := alpha * float64(h.m) * float64(h.m) / sum

	// Linear counting for small range corrections
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

// Merge merges the registers of another HyperLogLog into this one.
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
