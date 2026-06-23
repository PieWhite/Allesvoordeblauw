// detector_results.go handles extraction and formatting of detection results.
// It converts raw probability maps into structured MLResult slices, applying
// subnet filtering and explainability annotations.
package engine

import (
	"goversion/config"
	"goversion/models"
)

func (d *Detector) FlushResults(seen *HyperLogLog) []models.MLResult {
	if d.completedWindows != nil {
		d.Flush()
		close(d.completedWindows)
		d.evalWg.Wait()
	}

	d.probMutex.Lock()
	defer d.probMutex.Unlock()

	results := d.formatResults(d.maxProbs)

	if seen != nil && d.SeenIPs != nil {
		seen.Merge(d.SeenIPs)
	}

	d.maxProbs = make(map[uint32]float64)
	d.maxFeatures = make(map[uint32][]float64)
	d.topBenign = d.topBenign[:0]
	d.windowManager = NewNetflowWindowManager(d.windowManager.policy)
	d.TotalRecords = 0
	d.SeenIPs = NewHyperLogLog(14)

	d.startWorkers()

	return results
}

func (d *Detector) CalculateResults() ([]models.MLResult, int) {
	if d.completedWindows != nil {
		d.Flush()
		close(d.completedWindows)
		d.evalWg.Wait()
	}

	d.probMutex.Lock()
	defer d.probMutex.Unlock()

	uniqueCount := 0
	if d.SeenIPs != nil {
		uniqueCount = d.SeenIPs.Estimate()
	}
	return d.formatResults(d.maxProbs), uniqueCount
}

func (d *Detector) formatResults(probs map[uint32]float64) []models.MLResult {
	const threshold = 0.50
	realResults := []models.MLResult{}

	for ip, prob := range probs {
		ipStr := FormatIPv4(ip)
		if d.Subnet != "" && !config.MatchSubnet(ipStr, d.Subnet) {
			continue
		}
		if prob > threshold {
			var expl string
			if d.explainer != nil {
				if feats, ok := d.maxFeatures[ip]; ok {
					expl = d.explainer.FormatExplanation(feats)
				}
			}
			realResults = append(realResults, models.MLResult{
				IP:          ipStr,
				Probability: prob * 100.0,
				IsBotnet:    true,
				Explanation: expl,
			})
		}
	}

	for _, info := range d.topBenign {
		ipStr := FormatIPv4(info.IP)
		if d.Subnet != "" && !config.MatchSubnet(ipStr, d.Subnet) {
			continue
		}
		if info.Prob <= threshold {
			realResults = append(realResults, models.MLResult{
				IP:          ipStr,
				Probability: info.Prob * 100.0,
				IsBotnet:    false,
			})
		}
	}

	return realResults
}
