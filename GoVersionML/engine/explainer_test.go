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

func TestExplainer_FormatExplanation_Integration(t *testing.T) {
	// Verify that FormatExplanation correctly:
	// 1. Sorts and limits to the top 4 contributions.
	// 2. Integrates with the custom feature formatting.
	// 3. Joins the results.
	trees := []ModelNode{
		{NodeID: 0, Split: "f0", SplitCondition: 10, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(1.0)}}},
		{NodeID: 0, Split: "f1", SplitCondition: 10, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(2.0)}}},
		{NodeID: 0, Split: "f2", SplitCondition: 10, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(3.0)}}},
		{NodeID: 0, Split: "f3", SplitCondition: 10, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(4.0)}}},
		{NodeID: 0, Split: "f4", SplitCondition: 10, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(5.0)}}},
	}

	explainer := &Explainer{
		Trees:        trees,
		FeatureNames: []string{"A", "B", "C", "D", "E"},
	}

	features := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	explanation := explainer.FormatExplanation(features)

	// Since f4 has the highest contribution, it is sorted first. 
	// The fifth feature (f0 / "A") should be excluded as limit is 4.
	expected := "Reasons: E (5.00), D (4.00), C (3.00), B (2.00)"
	if explanation != expected {
		t.Errorf("expected explanation %q, got %q", expected, explanation)
	}
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

func TestExplainer_FeatureNameResolution(t *testing.T) {
	// 1. Fallback to package-level FeatureNames
	expDefault := &Explainer{
		Trees: []ModelNode{
			{NodeID: 0, Split: "f0", SplitCondition: 100.0, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(1.0)}}},
		},
	}
	// FeatureNames[0] is "flow_count". With default format, flow_count is an integer -> %.0f.
	explDefault := expDefault.FormatExplanation([]float64{42.0})
	if !strings.Contains(explDefault, "flow_count (42)") {
		t.Errorf("expected fallback to default flow_count formatting, got %q", explDefault)
	}

	// 2. Custom PcapFeatureNames
	expPcap := &Explainer{
		Trees: []ModelNode{
			{NodeID: 0, Split: "f0", SplitCondition: 100.0, Yes: 1, Children: []ModelNode{{NodeID: 1, Leaf: floatPtr(1.0)}}},
		},
		FeatureNames: PcapFeatureNames,
	}
	// PcapFeatureNames[0] is "Header_Length". With Header_Length format -> %.1fB.
	explPcap := expPcap.FormatExplanation([]float64{64.0})
	if !strings.Contains(explPcap, "Header_Length (64.0B)") {
		t.Errorf("expected fallback to Pcap Header_Length formatting, got %q", explPcap)
	}
}

func TestFeatureContribution_FormatValue(t *testing.T) {
	tests := []struct {
		name     string
		contrib  FeatureContribution
		expected string
	}{
		{
			name: "Percentage formatting pct_tcp",
			contrib: FeatureContribution{
				Name:  "pct_tcp",
				Value: 12.34,
			},
			expected: "12.3%",
		},
		{
			name: "Proportion to percentage conversion HTTP",
			contrib: FeatureContribution{
				Name:  "HTTP",
				Value: 0.1234,
			},
			expected: "12.3%",
		},
		{
			name: "Integer formatting flow_count",
			contrib: FeatureContribution{
				Name:  "flow_count",
				Value: 123.45,
			},
			expected: "123",
		},
		{
			name: "Bytes formatting B",
			contrib: FeatureContribution{
				Name:  "total_bytes",
				Value: 512,
			},
			expected: "512B",
		},
		{
			name: "Bytes formatting KB",
			contrib: FeatureContribution{
				Name:  "total_bytes",
				Value: 1536,
			},
			expected: "1.5KB",
		},
		{
			name: "Bytes formatting MB",
			contrib: FeatureContribution{
				Name:  "total_bytes",
				Value: 1024 * 1024 * 3.5,
			},
			expected: "3.5MB",
		},
		{
			name: "Time duration avg_duration",
			contrib: FeatureContribution{
				Name:  "avg_duration",
				Value: 0.0456,
			},
			expected: "0.046s",
		},
		{
			name: "Size in bytes Header_Length",
			contrib: FeatureContribution{
				Name:  "Header_Length",
				Value: 64,
			},
			expected: "64.0B",
		},
		{
			name: "Rate pps",
			contrib: FeatureContribution{
				Name:  "Rate",
				Value: 1000.5,
			},
			expected: "1000.5 pps",
		},
		{
			name: "Protocol Type TCP",
			contrib: FeatureContribution{
				Name:  "Protocol Type",
				Value: 6.0,
			},
			expected: "TCP",
		},
		{
			name: "Protocol Type UDP",
			contrib: FeatureContribution{
				Name:  "Protocol Type",
				Value: 17.0,
			},
			expected: "UDP",
		},
		{
			name: "Protocol Type Unknown",
			contrib: FeatureContribution{
				Name:  "Protocol Type",
				Value: 99.0,
			},
			expected: "99",
		},
		{
			name: "Default formatting unknown feature",
			contrib: FeatureContribution{
				Name:  "unknown_feat",
				Value: 12.345,
			},
			expected: "12.35",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.contrib.FormatValue()
			if actual != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, actual)
			}
		})
	}
}
