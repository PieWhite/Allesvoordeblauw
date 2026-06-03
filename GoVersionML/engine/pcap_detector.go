package engine

import (
	"fmt"
	"log"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"goversion/config"
	"goversion/models"

	xgboost "github.com/Elvenson/xgboost-go"
	"github.com/Elvenson/xgboost-go/activation"
	"github.com/Elvenson/xgboost-go/mat"
)

// PcapDetector performs statistical evaluation on raw PCAP packets using the 39-feature model
type PcapDetector struct {
	TotalRecords   int64
	pcapAggregator *PcapAggregator
	model          XGBoostModel

	maxProbs      map[string]float64
	maxFeatures   map[string][]float64
	topBenign     []BenignIPInfo
	explainer     *Explainer
	probMutex     sync.Mutex
	currentWindow atomic.Int64
	Subnet        string
}

func NewPcapDetector(modelPath string) (*PcapDetector, error) {
	loadedModel, err := xgboost.LoadXGBoostFromJSON(modelPath, "", 1, 6, &activation.Logistic{})
	if err != nil {
		return nil, fmt.Errorf("failed to load PCAP model: %w", err)
	}

	explainer, err := NewExplainer(modelPath, PcapFeatureNames)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PCAP explainer: %w", err)
	}

	return &PcapDetector{
		pcapAggregator: NewPcapAggregator(),
		model:          loadedModel,
		maxProbs:       make(map[string]float64),
		maxFeatures:    make(map[string][]float64),
		topBenign:      make([]BenignIPInfo, 0, 10),
		explainer:      explainer,
	}, nil
}

// TotalCount returns the total number of records processed.
func (d *PcapDetector) TotalCount() int64 {
	return atomic.LoadInt64(&d.TotalRecords)
}

// ProcessPcapRecords streams a batch of PCAP records into the pcapAggregator
func (d *PcapDetector) ProcessPcapRecords(records []models.PcapRecord) {
	var localMaxWindow int64
	var matchedCount int64

	for _, record := range records {
		if d.Subnet != "" && !config.MatchSubnet(record.SrcIP, d.Subnet) && !config.MatchSubnet(record.DstIP, d.Subnet) {
			continue
		}
		matchedCount++
		d.pcapAggregator.Update(record)

		// Sniff timestamp for flushing logic (5-minute windows)
		win := int64(record.Timestamp) / 300 * 300
		if win > localMaxWindow {
			localMaxWindow = win
		}
	}

	atomic.AddInt64(&d.TotalRecords, matchedCount)

	if localMaxWindow > 0 {
		d.updateMaxWindowAndFlush(localMaxWindow)
	}
}

func (d *PcapDetector) updateMaxWindowAndFlush(win int64) {
	curr := d.currentWindow.Load()
	for win > curr {
		if d.currentWindow.CompareAndSwap(curr, win) {
			// Flush data older than (maxWindow - 5 minutes)
			d.flushOldWindows(win - 300)
			break
		}
		curr = d.currentWindow.Load()
	}
}

func (d *PcapDetector) flushOldWindows(threshold int64) {
	flushed := d.pcapAggregator.ExtractAndFlushBefore(threshold)
	if len(flushed) == 0 {
		return
	}

	d.evaluateBatch(flushed)
}

func (d *PcapDetector) evaluateBatch(statsBatch []*PcapIPStats) {
	if len(statsBatch) == 0 {
		return
	}

	vectors := make([]mat.SparseVector, len(statsBatch))

	// Worker pool: cap concurrency to NumCPU to avoid scheduler flooding on large batches
	type job struct {
		idx   int
		stats *PcapIPStats
	}
	numWorkers := runtime.NumCPU()
	if numWorkers > len(statsBatch) {
		numWorkers = len(statsBatch)
	}
	jobs := make(chan job, len(statsBatch))
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				features := j.stats.ToPcapMLVector()
				sv := make(mat.SparseVector)
				for fIdx, val := range features {
					if val != 0 {
						sv[fIdx] = float32(val)
					}
				}
				vectors[j.idx] = sv
			}
		}()
	}
	for idx, stats := range statsBatch {
		jobs <- job{idx: idx, stats: stats}
	}
	close(jobs)
	wg.Wait()

	input := mat.SparseMatrix{
		Vectors: vectors,
	}

	preds, err := d.model.PredictProba(input)
	if err != nil {
		log.Printf("Error in PCAP batch prediction: %v", err)
		return
	}

	d.probMutex.Lock()
	if d.maxProbs == nil {
		d.maxProbs = make(map[string]float64)
	}
	if d.maxFeatures == nil {
		d.maxFeatures = make(map[string][]float64)
	}
	for idx, vPtr := range preds.Vectors {
		if vPtr == nil || len(*vPtr) == 0 {
			continue
		}
		prob := float64((*vPtr)[0])
		ip := statsBatch[idx].IP

		if currentMax, exists := d.maxProbs[ip]; !exists || prob > currentMax {
			d.maxProbs[ip] = prob

			if prob > 0.50 {
				d.maxFeatures[ip] = statsBatch[idx].ToPcapMLVector()
				for i, info := range d.topBenign {
					if info.IP == ip {
						d.topBenign = append(d.topBenign[:i], d.topBenign[i+1:]...)
						break
					}
				}
			} else {
				d.updateTopBenign(ip, prob, statsBatch[idx])
			}
		}
	}
	d.probMutex.Unlock()
}

func (d *PcapDetector) updateTopBenign(ip string, prob float64, stats *PcapIPStats) {
	foundIdx := -1
	for i, info := range d.topBenign {
		if info.IP == ip {
			foundIdx = i
			break
		}
	}

	if foundIdx != -1 {
		if prob > d.topBenign[foundIdx].Prob {
			d.topBenign[foundIdx].Prob = prob
			d.maxFeatures[ip] = stats.ToPcapMLVector()
			sort.Slice(d.topBenign, func(i, j int) bool {
				return d.topBenign[i].Prob > d.topBenign[j].Prob
			})
		}
		return
	}

	if len(d.topBenign) < 10 {
		d.topBenign = append(d.topBenign, BenignIPInfo{IP: ip, Prob: prob})
		d.maxFeatures[ip] = stats.ToPcapMLVector()
		sort.Slice(d.topBenign, func(i, j int) bool {
			return d.topBenign[i].Prob > d.topBenign[j].Prob
		})
		return
	}

	minBenignProb := d.topBenign[9].Prob
	if prob > minBenignProb {
		evictedIP := d.topBenign[9].IP
		delete(d.maxFeatures, evictedIP)

		d.topBenign[9] = BenignIPInfo{IP: ip, Prob: prob}
		d.maxFeatures[ip] = stats.ToPcapMLVector()
		sort.Slice(d.topBenign, func(i, j int) bool {
			return d.topBenign[i].Prob > d.topBenign[j].Prob
		})
	}
}

// Flush processes all remaining active stats currently in the aggregator
func (d *PcapDetector) Flush() {
	flushed := d.pcapAggregator.FlushAll()
	if len(flushed) > 0 {
		d.evaluateBatch(flushed)
	}
}

// CalculateResults flushes remaining records and formats output
func (d *PcapDetector) CalculateResults() []models.MLResult {
	d.Flush()

	d.probMutex.Lock()
	defer d.probMutex.Unlock()
	return d.formatResults(d.maxProbs)
}

func (d *PcapDetector) formatResults(probs map[string]float64) []models.MLResult {
	const threshold = 0.50
	var realResults []models.MLResult

	for ip, prob := range probs {
		if d.Subnet != "" && !config.MatchSubnet(ip, d.Subnet) {
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
				IP:          ip,
				Probability: prob * 100.0,
				IsBotnet:    true,
				Explanation: expl,
			})
		}
	}

	for _, info := range d.topBenign {
		if d.Subnet != "" && !config.MatchSubnet(info.IP, d.Subnet) {
			continue
		}
		if info.Prob <= threshold {
			realResults = append(realResults, models.MLResult{
				IP:          info.IP,
				Probability: info.Prob * 100.0,
				IsBotnet:    false,
			})
		}
	}

	totalUniqueIPs := len(probs)
	results := make([]models.MLResult, totalUniqueIPs)
	copy(results, realResults)
	return results
}
