// explainer.go implements tree-path-based feature contribution analysis for
// XGBoost models. It traces decision paths through the model's JSON tree dump
// and distributes leaf values across the features encountered along each path.
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

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
	Trees        []ModelNode
	FeatureNames []string
}

func NewExplainer(modelPath string, featureNames []string) (*Explainer, error) {
	data, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read model file: %w", err)
	}

	var trees []ModelNode
	if err := json.Unmarshal(data, &trees); err != nil {
		return nil, fmt.Errorf("failed to parse model JSON: %w", err)
	}

	return &Explainer{
		Trees:        trees,
		FeatureNames: featureNames,
	}, nil
}

type FeatureContribution struct {
	Index        int
	Name         string
	Value        float64
	Contribution float64
}

func (e *Explainer) Explain(features []float64) []FeatureContribution {
	featureNames := e.FeatureNames
	if len(featureNames) == 0 {
		featureNames = FeatureNames
	}
	contributions := make([]float64, len(featureNames))

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
			var name string
			if idx < len(featureNames) {
				name = featureNames[idx]
			} else {
				name = fmt.Sprintf("f%d", idx)
			}
			results = append(results, FeatureContribution{
				Index:        idx,
				Name:         name,
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
		case "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
			"IGMP", "HTTPS", "HTTP", "Telnet", "DNS", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC":
			valStr = fmt.Sprintf("%.1f%%", c.Value*100.0)
		case "flow_count", "unique_dst_ips", "unique_dst_ports", "total_packets",
			"syn_count", "ack_count", "fin_count", "rst_count", "Number", "Time_To_Live":
			valStr = fmt.Sprintf("%.0f", c.Value)
		case "total_bytes", "Tot sum":
			if c.Value >= 1024*1024 {
				valStr = fmt.Sprintf("%.1fMB", c.Value/(1024*1024))
			} else if c.Value >= 1024 {
				valStr = fmt.Sprintf("%.1fKB", c.Value/1024)
			} else {
				valStr = fmt.Sprintf("%.0fB", c.Value)
			}
		case "avg_duration", "iat_mean", "IAT":
			valStr = fmt.Sprintf("%.3fs", c.Value)
		case "Header_Length", "Min", "Max", "AVG", "Tot size":
			valStr = fmt.Sprintf("%.1fB", c.Value)
		case "Rate":
			valStr = fmt.Sprintf("%.1f pps", c.Value)
		case "Protocol Type":
			switch int(c.Value) {
			case 6:
				valStr = "TCP"
			case 17:
				valStr = "UDP"
			case 1:
				valStr = "ICMP"
			case 2:
				valStr = "IGMP"
			default:
				valStr = fmt.Sprintf("%.0f", c.Value)
			}
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
