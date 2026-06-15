package pipeline

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
	"goversion/scanner"
)

// classifiedFiles groups discovered files by their supported type.
type classifiedFiles struct {
	json        []string
	ndjson      []string
	csv         []string
	pcap        []string
	unsupported []string
}

// RunPipelineForInput is the main entry point. It delegates to single-file
// or directory processing based on the input path.
func RunPipelineForInput(cfg *config.AppConfig) ([]models.MLResult, int, int64, error) {
	info, err := os.Stat(cfg.InputPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to stat input path: %w", err)
	}

	if !info.IsDir() {
		return routeSingleFile(cfg)
	}

	return runDirectoryPipeline(cfg)
}

// routeSingleFile dispatches a single file to the correct scanner based on extension.
func routeSingleFile(cfg *config.AppConfig) ([]models.MLResult, int, int64, error) {
	ext := strings.ToLower(filepath.Ext(cfg.InputPath))

	switch ext {
	case ".pcap":
		resolved := resolveModelPath(true)
		return AnalyzePcapFile(cfg, resolved, scanner.StreamPCAP)
	case ".ndjson":
		resolved := resolveModelPath(false)
		return AnalyzeFile(cfg, resolved, scanner.StreamNDJSON)
	case ".json":
		resolved := resolveModelPath(false)
		return AnalyzeFile(cfg, resolved, scanner.StreamJSON)
	case ".csv":
		resolved := resolveModelPath(false)
		return AnalyzeFile(cfg, resolved, scanner.StreamCSV)
	default:
		return nil, 0, 0, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

func runDirectoryPipeline(cfg *config.AppConfig) ([]models.MLResult, int, int64, error) {
	classified, err := classifyDirectory(cfg.InputPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("error walking directory: %w", err)
	}

	totalFiles := len(classified.json) + len(classified.ndjson) + len(classified.pcap) + len(classified.csv)
	if totalFiles == 0 {
		return nil, 0, 0, fmt.Errorf("no .json, .ndjson, .csv or .pcap files found in directory")
	}

	if len(classified.unsupported) > 0 && !Silence {
		fmt.Printf("Unsupported file types detected (%d files). These will be skipped.\n", len(classified.unsupported))
	}

	if !cfg.SkipConfirm {
		if err := confirmDirectoryParse(classified); err != nil {
			return nil, 0, 0, err
		}
	}

	return processBatch(cfg, classified, totalFiles)
}

func classifyDirectory(dirPath string) (classifiedFiles, error) {
	var cf classifiedFiles

	err := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			cf.json = append(cf.json, path)
		case ".ndjson":
			cf.ndjson = append(cf.ndjson, path)
		case ".pcap":
			cf.pcap = append(cf.pcap, path)
		case ".csv":
			cf.csv = append(cf.csv, path)
		default:
			cf.unsupported = append(cf.unsupported, path)
		}
		return nil
	})

	return cf, err
}

func confirmDirectoryParse(cf classifiedFiles) error {
	jsonCount := len(cf.json)
	ndjsonCount := len(cf.ndjson)
	pcapCount := len(cf.pcap)
	csvCount := len(cf.csv)

	switch {
	case jsonCount > 0 && ndjsonCount == 0 && pcapCount == 0 && csvCount == 0:
		fmt.Printf("The following file type has been detected: json (%d files). Continue with json parsing? [y/N]: ", jsonCount)
	case ndjsonCount > 0 && jsonCount == 0 && pcapCount == 0 && csvCount == 0:
		fmt.Printf("The following file type has been detected: ndjson (%d files). Continue with ndjson parsing? [y/N]: ", ndjsonCount)
	case pcapCount > 0 && jsonCount == 0 && ndjsonCount == 0 && csvCount == 0:
		fmt.Printf("The following file type has been detected: pcap (%d files). Continue with pcap parsing? [y/N]: ", pcapCount)
	case csvCount > 0 && jsonCount == 0 && ndjsonCount == 0 && pcapCount == 0:
		fmt.Printf("The following file type has been detected: csv (%d files). Continue with csv parsing? [y/N]: ", csvCount)

	default:
		fmt.Printf("The following file types have been detected: json (%d files) ndjson (%d files) pcap (%d files) csv (%d files).\n", jsonCount, ndjsonCount, pcapCount, csvCount)
		fmt.Print("Continue parsing mixed file types (experimental)? [y/N]: ")
	}

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		return fmt.Errorf("parsing cancelled by user")
	}
	return nil
}

func processBatch(cfg *config.AppConfig, cf classifiedFiles, totalFiles int) ([]models.MLResult, int, int64, error) {
	// Pre-load models to fail fast if they are unavailable
	if len(cf.json) > 0 || len(cf.ndjson) > 0 || len(cf.csv) > 0 {
		resolved := resolveModelPath(false)
		_, err := engine.NewDetector(resolved)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed loading xgboost model for Netflow: %w", err)
		}
	}

	if len(cf.pcap) > 0 {
		resolved := resolveModelPath(true)
		_, err := engine.NewPcapDetector(resolved)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed loading xgboost model for PCAP: %w", err)
		}
	}

	allFiles := make([]string, 0, totalFiles)
	allFiles = append(allFiles, cf.json...)
	allFiles = append(allFiles, cf.ndjson...)
	allFiles = append(allFiles, cf.pcap...)
	allFiles = append(allFiles, cf.csv...)

	var totalRecords atomic.Int64
	var allResults []models.MLResult
	var resultsMutex sync.Mutex
	seenIPs := engine.NewHyperLogLog(14)
	var seenMutex sync.Mutex

	type fileJob struct {
		Index int
		Path  string
	}
	jobs := make(chan fileJob, totalFiles)
	for i, file := range allFiles {
		jobs <- fileJob{Index: i, Path: file}
	}
	close(jobs)

	// A single file parse kicks off numCPU/2 internal workers.
	// Cap file-level concurrency to avoid extreme thrashing or OOM.
	numWorkers := runtime.NumCPU()

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var netflowDetector *engine.Detector
			var pcapDetector *engine.PcapDetector

			// Each worker holds its own Detector instance for strict 5-min window isolation safely
			if len(cf.json) > 0 || len(cf.ndjson) > 0 || len(cf.csv) > 0 {
				netflowDetector, _ = engine.NewDetector(resolveModelPath(false))
				if netflowDetector != nil && cfg != nil {
					netflowDetector.Subnet = cfg.Subnet
				}
			}
			if len(cf.pcap) > 0 {
				pcapDetector, _ = engine.NewPcapDetector(resolveModelPath(true))
				if pcapDetector != nil && cfg != nil {
					pcapDetector.Subnet = cfg.Subnet
				}
			}

			localSeenIPs := engine.NewHyperLogLog(14)
			var localResults []models.MLResult

			for job := range jobs {
				if !Silence {
					fmt.Printf("Processing file %d/%d: %s\n", job.Index+1, totalFiles, filepath.Base(job.Path))
				}
				ext := strings.ToLower(filepath.Ext(job.Path))
				var count int64
				var err error

				if ext == ".pcap" && pcapDetector != nil {
					count, err = ProcessPcapFile(job.Path, pcapDetector, scanner.StreamPCAP)
					if err == nil {
						localResults = append(localResults, pcapDetector.FlushResults(localSeenIPs)...)
					}
				} else if netflowDetector != nil {
					if ext == ".csv" {
						count, err = ProcessFile(job.Path, netflowDetector, scanner.StreamCSV)
					} else if ext == ".json" {
						count, err = ProcessFile(job.Path, netflowDetector, scanner.StreamJSON)
					} else if ext == ".ndjson" {
						count, err = ProcessFile(job.Path, netflowDetector, scanner.StreamNDJSON)
					}

					if err == nil {
						localResults = append(localResults, netflowDetector.FlushResults(localSeenIPs)...)
					}
				}

				if err != nil {
					if !Silence {
						fmt.Printf("Error processing %s: %v\n", job.Path, err)
					}
				} else {
					totalRecords.Add(count)
				}
			}

			resultsMutex.Lock()
			allResults = append(allResults, localResults...)
			resultsMutex.Unlock()

			seenMutex.Lock()
			seenIPs.Merge(localSeenIPs)
			seenMutex.Unlock()
		}()
	}
	wg.Wait()

	// Deduplicate: keep only the highest score per IP across all files
	allResults = deduplicateMaxScore(allResults)

	return allResults, seenIPs.Estimate(), totalRecords.Load(), nil
}

// deduplicateMaxScore keeps only the highest-scoring entry per IP.
// This preserves the original behavior where maxProbs tracked the global
// maximum, but without holding all IPs in memory simultaneously.
func deduplicateMaxScore(results []models.MLResult) []models.MLResult {
	if len(results) == 0 {
		return results
	}

	best := make(map[string]int) // IP -> index into deduped
	var deduped []models.MLResult

	for _, r := range results {
		if r.IP == "" {
			continue
		}
		if idx, exists := best[r.IP]; exists {
			if r.Probability > deduped[idx].Probability {
				deduped[idx] = r
			}
		} else {
			best[r.IP] = len(deduped)
			deduped = append(deduped, r)
		}
	}

	return deduped
}

func streamFnFor(path string) StreamFn {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		return scanner.StreamJSON
	} else if ext == ".csv" {
		return scanner.StreamCSV
	}
	return scanner.StreamNDJSON
}

var (
	NetflowModelPath = "Xgboost/botnet_xgboost.json"
	PcapModelPath    = "Xgboost/pcap_xgboost.json"
	Silence          = false
)

func resolveModelPath(isPcap bool) string {
	if isPcap {
		return getExistingPath(PcapModelPath)
	}
	return getExistingPath(NetflowModelPath)
}

func getExistingPath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return "../" + path
}
