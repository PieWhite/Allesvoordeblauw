// explainer_test.go verifies XGBoost tree-path feature contribution analysis
// and human-readable explanation formatting across Netflow and PCAP feature sets.
package engine

import (
	"strings"
	"testing"
)

func floatPtr(val float64) *float64 {
	return &val
}

func TestExplainer_ExplainAndFormat(t *testing.T) {
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
		features := []float64{5.0}
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
		features := []float64{15.0}
		contributions := explainer.Explain(features)

		if len(contributions) != 1 {
			t.Fatalf("expected 1 contribution, got %d", len(contributions))
		}
		if contributions[0].Contribution != 2.0 {
			t.Errorf("expected contribution 2.0, got %f", contributions[0].Contribution)
		}
	})

	t.Run("Shorter feature slice (Out of Bounds)", func(t *testing.T) {
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

		contributions := explainer.Explain(features)
		if len(contributions) != 0 {
			t.Errorf("expected 0 contributions, got %d", len(contributions))
		}
	})

	t.Run("Index exceeds length of features", func(t *testing.T) {
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

		contributions := explainer.Explain(features)
		if len(contributions) != 0 {
			t.Errorf("expected 0 contributions, got %d", len(contributions))
		}
	})
}

func TestExplainer_FormatExplanation_Types(t *testing.T) {
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
	features[0] = 120.0
	features[3] = 1536.0
	features[7] = 85.5
	features[12] = 0.0456

	explanation := explainer.FormatExplanation(features)

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

		featsMB := make([]float64, 21)
		featsMB[3] = 2.5 * 1024 * 1024
		explMB := expMB.FormatExplanation(featsMB)
		if !strings.Contains(explMB, "total_bytes (2.5MB)") {
			t.Errorf("expected total_bytes formatting in MB, got: %s", explMB)
		}

		featsB := make([]float64, 21)
		featsB[3] = 256.0
		explB := expMB.FormatExplanation(featsB)
		if !strings.Contains(explB, "total_bytes (256B)") {
			t.Errorf("expected total_bytes formatting in B, got: %s", explB)
		}
	})
}

func TestExplainer_FormatExplanation_EmptyContributions(t *testing.T) {
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
	features := []float64{4.0, 3.0}
	contributions := explainer.Explain(features)

	if len(contributions) != 2 {
		t.Fatalf("expected 2 contributions, got %d", len(contributions))
	}

	for _, c := range contributions {
		if c.Contribution != 3.0 {
			t.Errorf("expected contribution of 3.0 for feature %s, got %f", c.Name, c.Contribution)
		}
	}
}

func TestExplainer_PCAPFormatting(t *testing.T) {
	trees := []ModelNode{
		{
			NodeID:         0,
			Split:          "f0",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(1.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f2",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(2.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f3",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(3.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f10",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(4.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f29",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(5.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f35",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(6.0)},
			},
		},
		{
			NodeID:         0,
			Split:          "f38",
			SplitCondition: 99999999.0,
			Yes:            1,
			Children: []ModelNode{
				{NodeID: 1, Leaf: floatPtr(7.0)},
			},
		},
	}

	explainer := &Explainer{
		Trees:        trees,
		FeatureNames: PcapFeatureNames,
	}

	features := make([]float64, 39)
	features[0] = 54.2
	features[2] = 2304.5
	features[3] = 0.4578
	features[10] = 120.0
	features[29] = 10.5 * 1024 * 1024
	features[35] = 0.00456
	features[38] = 6.0

	explanation := explainer.FormatExplanation(features)

	if !strings.Contains(explanation, "Protocol Type (TCP)") {
		t.Errorf("expected Protocol Type TCP formatting, got: %s", explanation)
	}
	if !strings.Contains(explanation, "IAT (0.005s)") {
		t.Errorf("expected IAT formatting, got: %s", explanation)
	}
	if !strings.Contains(explanation, "Tot sum (10.5MB)") {
		t.Errorf("expected Tot sum formatting, got: %s", explanation)
	}
	if !strings.Contains(explanation, "syn_count (120)") {
		t.Errorf("expected syn_count formatting, got: %s", explanation)
	}

	if strings.Contains(explanation, "Header_Length") {
		t.Errorf("expected Header_Length to be excluded due to top 4 limit, got: %s", explanation)
	}
}
