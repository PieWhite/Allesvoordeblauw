// model_cache.go provides thread-safe singleton caching for FastXGBoost models
// and Explainer instances. Multiple detectors sharing the same model path will
// reuse the same in-memory structures.
package engine

import "sync"

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
