package engine

import (
	"strings"
	"testing"
)

func floatPtr(val float64) *float64 {
	return &val
}

func TestExplainer_ExplainAndFormat(t *testing.T) {
	// A simple mock tree:
	// If f0 < 10.0: Leaf = 1.0 (Yes)
	// Else: Leaf = 2.0 (No)
	tree := ModelNode{
		NodeID:         0,
		Split:          "f0",
		SplitCondition: 10.0,
		Yes:            1,
		No:             2,
		Children: []ModelNode{
			{
				NodeID: 1,
				Leaf:   floatPtr(1.0),
			},
			{
				NodeID: 2,
				Leaf:   floatPtr(2.0),
			},
		},
	}

	explainer := &Explainer{
		Trees: []ModelNode{tree},
	}

	t.Run("Valid features going left (Yes)", func(t *testing.T) {
		features := []float64{5.0} // f0 = 5.0, length is 1
		contributions := explainer.Explain(features)

		if len(contributions) != 1 {
			t.Fatalf("expected 1 contribution, got %d", len(contributions))
		}
		if contributions[0].Index != 0 {
			t.Errorf("expected feature index 0, got %d", contributions[0].Index)
		}
		if contributions[0].Value != 5.0 {
			t.Errorf("expected feature value 5.0, got %f", contributions[0].Value)
		}
		if contributions[0].Contribution != 1.0 {
			t.Errorf("expected contribution 1.0, got %f", contributions[0].Contribution)
		}

		explanation := explainer.FormatExplanation(features)
		if !strings.Contains(explanation, "flow_count (5)") {
			t.Errorf("expected explanation to contain flow_count (5), got %q", explanation)
		}
	})

	t.Run("Valid features going right (No)", func(t *testing.T) {
		features := []float64{15.0} // f0 = 15.0
		contributions := explainer.Explain(features)

		if len(contributions) != 1 {
			t.Fatalf("expected 1 contribution, got %d", len(contributions))
		}
		if contributions[0].Contribution != 2.0 {
			t.Errorf("expected contribution 2.0, got %f", contributions[0].Contribution)
		}
	})

	t.Run("Shorter feature slice (Out of Bounds)", func(t *testing.T) {
		// Empty features slice: length is 0. Accessing f0 would normally panic.
		// Now it should return early safely with no contributions.
		var emptyFeatures []float64
		contributions := explainer.Explain(emptyFeatures)
		if len(contributions) != 0 {
			t.Errorf("expected 0 contributions for empty features, got %d", len(contributions))
		}

		explanation := explainer.FormatExplanation(emptyFeatures)
		if explanation != "unknown reasons" {
			t.Errorf("expected 'unknown reasons' explanation, got %q", explanation)
		}
	})
}

func TestExplainer_InvalidSplitOrEdgeCases(t *testing.T) {
	t.Run("Invalid Split Format", func(t *testing.T) {
		// If split format is not 'f%d', Sscanf should fail and return early.
		tree := ModelNode{
			NodeID:         0,
			Split:          "invalid_split_format",
			SplitCondition: 10.0,
			Yes:            1,
			No:             2,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(1.0)},
				{NodeID: 2, Leaf: floatPtr(2.0)},
			},
		}

		explainer := &Explainer{Trees: []ModelNode{tree}}
		features := []float64{5.0, 6.0}

		// Should not panic, should return 0 contributions
		contributions := explainer.Explain(features)
		if len(contributions) != 0 {
			t.Errorf("expected 0 contributions, got %d", len(contributions))
		}
	})

	t.Run("Negative Feature Index in Split", func(t *testing.T) {
		tree := ModelNode{
			NodeID:         0,
			Split:          "f-5",
			SplitCondition: 10.0,
			Yes:            1,
			No:             2,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(1.0)},
				{NodeID: 2, Leaf: floatPtr(2.0)},
			},
		}

		explainer := &Explainer{Trees: []ModelNode{tree}}
		features := []float64{5.0, 6.0}

		// Should not panic, should return 0 contributions
		contributions := explainer.Explain(features)
		if len(contributions) != 0 {
			t.Errorf("expected 0 contributions, got %d", len(contributions))
		}
	})

	t.Run("Index exceeds length of features", func(t *testing.T) {
		// Tree checks f10, but features slice only has length 2
		tree := ModelNode{
			NodeID:         0,
			Split:          "f10",
			SplitCondition: 10.0,
			Yes:            1,
			No:             2,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(1.0)},
				{NodeID: 2, Leaf: floatPtr(2.0)},
			},
		}

		explainer := &Explainer{Trees: []ModelNode{tree}}
		features := []float64{5.0, 6.0}

		// Should not panic, should return 0 contributions
		contributions := explainer.Explain(features)
		if len(contributions) != 0 {
			t.Errorf("expected 0 contributions, got %d", len(contributions))
		}
	})
}

func TestExplainer_FormatExplanation_Types(t *testing.T) {
	// Let's create a tree that has multiple splits to accumulate contributions for different features.
	// Feature index 0: flow_count
	// Feature index 3: total_bytes
	// Feature index 7: pct_tcp
	// Feature index 12: avg_duration
	
	trees := []ModelNode{
		{
			NodeID:         0,
			Split:          "f0",
			SplitCondition: 1000.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(1.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f3",
			SplitCondition: 10000000.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(5.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f7",
			SplitCondition: 1000.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(10.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f12",
			SplitCondition: 1000.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(2.0)},
			},
		},
	}

	explainer := &Explainer{Trees: trees}
	
	features := make([]float64, 21)
	features[0] = 120.0             // flow_count (should format as "120")
	features[3] = 1536.0            // total_bytes (should format as "1.5KB")
	features[7] = 85.5              // pct_tcp (should format as "85.5%")
	features[12] = 0.0456           // avg_duration (should format as "0.046s")

	explanation := explainer.FormatExplanation(features)

	// Since contributions are sorted descending:
	// f7 (pct_tcp) has contribution 10.0
	// f3 (total_bytes) has contribution 5.0
	// f12 (avg_duration) has contribution 2.0
	// f0 (flow_count) has contribution 1.0
	
	if !strings.Contains(explanation, "pct_tcp (85.5%)") {
		t.Errorf("expected pct_tcp percentage formatting, got: %s", explanation)
	}
	if !strings.Contains(explanation, "total_bytes (1.5KB)") {
		t.Errorf("expected total_bytes formatting in KB, got: %s", explanation)
	}
	if !strings.Contains(explanation, "avg_duration (0.046s)") {
		t.Errorf("expected avg_duration time formatting, got: %s", explanation)
	}
	if !strings.Contains(explanation, "flow_count (120)") {
		t.Errorf("expected flow_count integer formatting, got: %s", explanation)
	}

	t.Run("Total bytes edge cases", func(t *testing.T) {
		// Test MB and B formatting
		bytesMBTree := []ModelNode{
			{
				NodeID:         0,
				Split:          "f3",
				SplitCondition: 10000000.0,
				Yes:            1,
				Children: []ModelNode{
					{NodeID: 1, Leaf: floatPtr(5.0)},
				},
			},
		}
		
		expMB := &Explainer{Trees: bytesMBTree}
		
		// 2.5 MB
		featsMB := make([]float64, 21)
		featsMB[3] = 2.5 * 1024 * 1024
		explMB := expMB.FormatExplanation(featsMB)
		if !strings.Contains(explMB, "total_bytes (2.5MB)") {
			t.Errorf("expected total_bytes formatting in MB, got: %s", explMB)
		}

		// 256 B
		featsB := make([]float64, 21)
		featsB[3] = 256.0
		explB := expMB.FormatExplanation(featsB)
		if !strings.Contains(explB, "total_bytes (256B)") {
			t.Errorf("expected total_bytes formatting in B, got: %s", explB)
		}
	})
}

func TestExplainer_FormatExplanation_EmptyContributions(t *testing.T) {
	// Trees that output 0 leaf values or has no trees at all
	explainer := &Explainer{
		Trees: []ModelNode{},
	}
	
	features := []float64{1.0, 2.0}
	explanation := explainer.FormatExplanation(features)
	if explanation != "unknown reasons" {
		t.Errorf("expected 'unknown reasons' for empty explainer, got %q", explanation)
	}
}

func TestExplainer_WeightedAverage(t *testing.T) {
	// A tree where a leaf value is reached via multiple features
	// Both f0 and f1 should split, sharing the leaf weight
	tree := ModelNode{
		NodeID:         0,
		Split:          "f0",
		SplitCondition: 10.0,
		Yes:            1,
		Children: []ModelNode{
			{
				NodeID:         1,
				Split:          "f1",
				SplitCondition: 5.0,
				Yes:            2,
				Children: []ModelNode{
					{
						NodeID: 2,
						Leaf:   floatPtr(6.0),
					},
				},
			},
		},
	}

	explainer := &Explainer{Trees: []ModelNode{tree}}
	features := []float64{4.0, 3.0} // both go Yes
	contributions := explainer.Explain(features)

	// Since we traverse f0 and f1, the contribution weight is split: 6.0 / 2 = 3.0 each
	if len(contributions) != 2 {
		t.Fatalf("expected 2 contributions, got %d", len(contributions))
	}
	
	for _, c := range contributions {
		if c.Contribution != 3.0 {
			t.Errorf("expected contribution of 3.0 for feature %s, got %f", c.Name, c.Contribution)
		}
	}
}
