package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
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

// PcapFeatureNames maps index f0 through f38 back to their PCAP human-readable names.
var PcapFeatureNames = []string{
	"Header_Length",    // f0
	"Time_To_Live",     // f1
	"Rate",             // f2
	"fin_flag_number",  // f3
	"syn_flag_number",  // f4
	"rst_flag_number",  // f5
	"psh_flag_number",  // f6
	"ack_flag_number",  // f7
	"ece_flag_number",  // f8
	"cwr_flag_number",  // f9
	"syn_count",        // f10
	"ack_count",        // f11
	"fin_count",        // f12
	"rst_count",        // f13
	"IGMP",             // f14
	"HTTPS",            // f15
	"HTTP",             // f16
	"Telnet",           // f17
	"DNS",              // f18
	"SMTP",             // f19
	"SSH",              // f20
	"IRC",              // f21
	"TCP",              // f22
	"UDP",              // f23
	"DHCP",             // f24
	"ARP",              // f25
	"ICMP",             // f26
	"IPv",              // f27
	"LLC",              // f28
	"Tot sum",          // f29
	"Min",              // f30
	"Max",              // f31
	"AVG",              // f32
	"Std",              // f33
	"Tot size",         // f34
	"IAT",              // f35
	"Number",           // f36
	"Variance",         // f37
	"Protocol Type",    // f38
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

// FormatValue returns the human-readable string representation of the feature value.
func (c FeatureContribution) FormatValue() string {
	switch c.Name {
	case "pct_tcp", "pct_udp", "pct_icmp", "pct_well_known_ports", "pct_high_ports", "pct_syn_only", "pct_rst":
		return fmt.Sprintf("%.1f%%", c.Value)
	case "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
		"IGMP", "HTTPS", "HTTP", "Telnet", "DNS", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC":
		return fmt.Sprintf("%.1f%%", c.Value*100.0)
	case "flow_count", "unique_dst_ips", "unique_dst_ports", "total_packets",
		"syn_count", "ack_count", "fin_count", "rst_count", "Number", "Time_To_Live":
		return fmt.Sprintf("%.0f", c.Value)
	case "total_bytes", "Tot sum":
		if c.Value >= 1024*1024 {
			return fmt.Sprintf("%.1fMB", c.Value/(1024*1024))
		} else if c.Value >= 1024 {
			return fmt.Sprintf("%.1fKB", c.Value/1024)
		} else {
			return fmt.Sprintf("%.0fB", c.Value)
		}
	case "avg_duration", "iat_mean", "IAT":
		return fmt.Sprintf("%.3fs", c.Value)
	case "Header_Length", "Min", "Max", "AVG", "Tot size":
		return fmt.Sprintf("%.1fB", c.Value)
	case "Rate":
		return fmt.Sprintf("%.1f pps", c.Value)
	case "Protocol Type":
		switch int(c.Value) {
		case 6:
			return "TCP"
		case 17:
			return "UDP"
		case 1:
			return "ICMP"
		case 2:
			return "IGMP"
		default:
			return fmt.Sprintf("%.0f", c.Value)
		}
	default:
		return fmt.Sprintf("%.2f", c.Value)
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
		parts = append(parts, fmt.Sprintf("%s (%s)", c.Name, c.FormatValue()))
	}

	if len(parts) == 0 {
		return "unknown reasons"
	}

	return "Reasons: " + strings.Join(parts, ", ")
}
