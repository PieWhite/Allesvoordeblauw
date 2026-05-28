package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// FeatureNames maps index f0 through f20 back to their human-readable names.
var FeatureNames = []string{
	"flow_count",             // f0
	"unique_dst_ips",         // f1
	"unique_dst_ports",       // f2
	"total_bytes",            // f3
	"total_packets",          // f4
	"avg_bytes_per_flow",     // f5
	"avg_packets_per_flow",   // f6
	"pct_tcp",                // f7
	"pct_udp",                // f8
	"pct_icmp",               // f9
	"pct_well_known_ports",   // f10
	"pct_high_ports",         // f11
	"avg_duration",           // f12
	"iat_mean",               // f13
	"iat_variance",           // f14
	"port_symmetry",          // f15
	"ip_port_ratio",          // f16
	"avg_payload_per_packet", // f17
	"pct_syn_only",           // f18
	"pct_rst",                // f19
	"iat_cv",                 // f20
}

type ModelNode struct {
	NodeID         int         `json:"nodeid"`
	Depth          int         `json:"depth"`
	Split          string      `json:"split,omitempty"`
	SplitCondition float64     `json:"split_condition,omitempty"`
	Yes            int         `json:"yes,omitempty"`
	No             int         `json:"no,omitempty"`
	Missing        int         `json:"missing,omitempty"`
	Leaf           *float64    `json:"leaf,omitempty"`
	Children       []ModelNode `json:"children,omitempty"`
}

type Explainer struct {
	Trees []ModelNode
}

func NewExplainer(modelPath string) (*Explainer, error) {
	data, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read model file: %w", err)
	}

	var trees []ModelNode
	if err := json.Unmarshal(data, &trees); err != nil {
		return nil, fmt.Errorf("failed to parse model JSON: %w", err)
	}

	return &Explainer{
		Trees: trees,
	}, nil
}

type FeatureContribution struct {
	Index        int
	Name         string
	Value        float64
	Contribution float64
}

func (e *Explainer) Explain(features []float64) []FeatureContribution {
	contributions := make([]float64, len(FeatureNames))

	for _, tree := range e.Trees {
		e.traceTree(tree, features, &contributions)
	}

	var results []FeatureContribution
	for idx, val := range contributions {
		if val != 0 {
			var featVal float64
			if idx < len(features) {
				featVal = features[idx]
			}
			results = append(results, FeatureContribution{
				Index:        idx,
				Name:         FeatureNames[idx],
				Value:        featVal,
				Contribution: val,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Contribution > results[j].Contribution
	})

	return results
}

func (e *Explainer) traceTree(node ModelNode, x []float64, contributions *[]float64) {
	var pathFeatures []int
	var leafVal float64

	var traverse func(n ModelNode)
	traverse = func(n ModelNode) {
		if n.Leaf != nil {
			leafVal = *n.Leaf
			return
		}

		var featIdx int
		if _, err := fmt.Sscanf(n.Split, "f%d", &featIdx); err != nil || featIdx < 0 || featIdx >= len(x) {
			return
		}
		pathFeatures = append(pathFeatures, featIdx)

		val := x[featIdx]
		nextID := n.No
		if val < n.SplitCondition {
			nextID = n.Yes
		}

		for _, child := range n.Children {
			if child.NodeID == nextID {
				traverse(child)
				return
			}
		}
	}

	traverse(node)

	if len(pathFeatures) > 0 && leafVal != 0 {
		weight := leafVal / float64(len(pathFeatures))
		for _, featIdx := range pathFeatures {
			if featIdx < len(*contributions) {
				(*contributions)[featIdx] += weight
			}
		}
	}
}

func (e *Explainer) FormatExplanation(features []float64) string {
	contribs := e.Explain(features)
	if len(contribs) == 0 {
		return "unknown reasons"
	}

	limit := 4
	if len(contribs) < limit {
		limit = len(contribs)
	}

	var parts []string
	for i := 0; i < limit; i++ {
		c := contribs[i]

		valStr := ""
		switch c.Name {
		case "pct_tcp", "pct_udp", "pct_icmp", "pct_well_known_ports", "pct_high_ports", "pct_syn_only", "pct_rst":
			valStr = fmt.Sprintf("%.1f%%", c.Value)
		case "flow_count", "unique_dst_ips", "unique_dst_ports", "total_packets":
			valStr = fmt.Sprintf("%.0f", c.Value)
		case "total_bytes":
			if c.Value >= 1024*1024 {
				valStr = fmt.Sprintf("%.1fMB", c.Value/(1024*1024))
			} else if c.Value >= 1024 {
				valStr = fmt.Sprintf("%.1fKB", c.Value/1024)
			} else {
				valStr = fmt.Sprintf("%.0fB", c.Value)
			}
		case "avg_duration", "iat_mean":
			valStr = fmt.Sprintf("%.3fs", c.Value)
		default:
			valStr = fmt.Sprintf("%.2f", c.Value)
		}

		parts = append(parts, fmt.Sprintf("%s (%s)", c.Name, valStr))
	}

	if len(parts) == 0 {
		return "unknown reasons"
	}

	explanation := "Reasons: "
	for i, part := range parts {
		if i > 0 {
			explanation += ", "
		}
		explanation += part
	}
	return explanation
}
