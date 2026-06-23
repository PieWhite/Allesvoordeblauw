// fast_xgboost.go implements a dense-array optimized XGBoost ensemble evaluator.
// It loads XGBoost JSON tree dumps into a flattened node array for O(1) node
// lookups during prediction, bypassing the overhead of map-based tree traversal.
package engine

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
)

type jsonNode struct {
	NodeID         int        `json:"nodeid"`
	Split          string     `json:"split"`
	SplitCondition float32    `json:"split_condition"`
	Yes            int        `json:"yes"`
	No             int        `json:"no"`
	Missing        int        `json:"missing"`
	Children       []jsonNode `json:"children"`
	Leaf           *float32   `json:"leaf"`
}

type FastNode struct {
	IsLeaf         bool
	LeafValue      float32
	SplitFeature   int
	SplitCondition float32
	Yes            int
	No             int
	Missing        int
}

type FastTree []FastNode

type FastXGBoost struct {
	Trees []FastTree
}

func parseFeature(f string) int {
	if len(f) > 1 && f[0] == 'f' {
		val, _ := strconv.Atoi(f[1:])
		return val
	}
	return -1
}

func getMaxNodeID(jn jsonNode) int {
	maxID := jn.NodeID
	for _, child := range jn.Children {
		childMax := getMaxNodeID(child)
		if childMax > maxID {
			maxID = childMax
		}
	}
	return maxID
}

func buildFastTree(jn jsonNode, tree []FastNode) {
	node := FastNode{}
	if jn.Leaf != nil {
		node.IsLeaf = true
		node.LeafValue = *jn.Leaf
	} else {
		node.IsLeaf = false
		node.SplitFeature = parseFeature(jn.Split)
		node.SplitCondition = jn.SplitCondition
		node.Yes = jn.Yes
		node.No = jn.No
		node.Missing = jn.Missing
	}
	tree[jn.NodeID] = node

	for _, child := range jn.Children {
		buildFastTree(child, tree)
	}
}

func LoadFastXGBoost(path string) (*FastXGBoost, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jsonTrees []jsonNode
	if err := json.Unmarshal(data, &jsonTrees); err != nil {
		return nil, err
	}

	fast := &FastXGBoost{
		Trees: make([]FastTree, len(jsonTrees)),
	}

	for i, jt := range jsonTrees {
		maxID := getMaxNodeID(jt)
		fast.Trees[i] = make(FastTree, maxID+1)
		buildFastTree(jt, fast.Trees[i])
	}
	return fast, nil
}

func (m *FastXGBoost) PredictProba(features []float32) float32 {
	var sum float32
	for _, tree := range m.Trees {
		curr := 0
		for {
			node := tree[curr]
			if node.IsLeaf {
				sum += node.LeafValue
				break
			}

			val := features[node.SplitFeature]
			if val != val {
				curr = node.Missing
			} else if val < node.SplitCondition {
				curr = node.Yes
			} else {
				curr = node.No
			}
		}
	}
	return float32(1.0 / (1.0 + math.Exp(float64(-sum))))
}
