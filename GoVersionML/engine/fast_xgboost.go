package engine

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
	"sync"
)

type jsonNode struct {
	NodeID         int         `json:"nodeid"`
	Split          string      `json:"split"`
	SplitCondition float32     `json:"split_condition"`
	Yes            int         `json:"yes"`
	No             int         `json:"no"`
	Missing        int         `json:"missing"`
	Children       []jsonNode  `json:"children"`
	Leaf           *float32    `json:"leaf"`
}

// FastNode represents a flattened, highly-optimized XGBoost decision tree node.
type FastNode struct {
	IsLeaf         bool
	LeafValue      float32
	SplitFeature   int
	SplitCondition float32
	Yes            int
	No             int
	Missing        int
}

// FastTree is a flattened array of nodes for O(1) traversal.
type FastTree []FastNode

// FastXGBoost is a custom, dense-array optimized XGBoost evaluator.
// It bypasses the slow map lookups of github.com/Elvenson/xgboost-go.
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

// LoadFastXGBoost loads an XGBoost Tree Dump (JSON) into an ultra-fast dense memory structure.
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

// PredictProba evaluates the dense feature array against the ensemble and returns a logistic probability.
// IMPORTANT: Missing features should be represented as math.NaN() in the input array.
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
			if math.IsNaN(float64(val)) {
				curr = node.Missing
			} else if val < node.SplitCondition {
				curr = node.Yes
			} else {
				curr = node.No
			}
		}
	}
	// Logistic sigmoid activation function
	return float32(1.0 / (1.0 + math.Exp(float64(-sum))))
}

var (
	modelCache       = make(map[string]*FastXGBoost)
	modelCacheMu     sync.Mutex
	explainerCache   = make(map[string]*Explainer)
	explainerCacheMu sync.Mutex
)

func GetOrLoadModel(path string) (*FastXGBoost, error) {
	modelCacheMu.Lock()
	defer modelCacheMu.Unlock()
	if m, ok := modelCache[path]; ok {
		return m, nil
	}
	m, err := LoadFastXGBoost(path)
	if err != nil {
		return nil, err
	}
	modelCache[path] = m
	return m, nil
}

func GetOrLoadExplainer(path string, featureNames []string) (*Explainer, error) {
	explainerCacheMu.Lock()
	defer explainerCacheMu.Unlock()
	if e, ok := explainerCache[path]; ok {
		return e, nil
	}
	e, err := NewExplainer(path, featureNames)
	if err != nil {
		return nil, err
	}
	explainerCache[path] = e
	return e, nil
}

