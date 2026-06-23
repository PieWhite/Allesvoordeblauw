// detector_eval_test.go verifies XGBoost batch evaluation and probability
// tracking for detected IPs.
package engine

import (
	"math"
	"testing"
)

func TestEvaluateBatch(t *testing.T) {
	d := &Detector{
		model: &FastXGBoost{
			Trees: []FastTree{
				{FastNode{IsLeaf: true, LeafValue: 0.84729786}},
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
