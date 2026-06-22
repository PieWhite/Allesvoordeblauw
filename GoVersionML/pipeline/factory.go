/*
Package pipeline orchestrates concurrent batch scanning of folders containing
multiple Netflow and PCAP files, managing memory scaling, models caching,
and IP communication counters.
*/
package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
	"goversion/scanner"
	"goversion/utils"
)

type classifiedFiles struct {
	json        []string
	ndjson      []string
	csv         []string
	pcap        []string
	unsupported []string
}

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

func routeSingleFile(cfg *config.AppConfig) ([]models.MLResult, int, int64, error) {
	ext := strings.ToLower(filepath.Ext(cfg.InputPath))
	ctx := context.Background()

	if ext == ".pcap" {
		res := RunPcapFilePipeline(ctx, cfg.InputPath, cfg)
		return res.Results, res.UniqueIPs, res.TotalRecords, res.Err
	}

	res := RunNetflowFilePipeline(ctx, cfg.InputPath, cfg)
	return res.Results, res.UniqueIPs, res.TotalRecords, res.Err
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
	// Set memory limit to prevent Go GC from allowing linear RAM scaling across workers
	debug.SetMemoryLimit(2500 * 1024 * 1024)

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

	globalResultsMap := make(map[string]models.MLResult)
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

	plan := utils.GetConcurrencyPlan()
	numWorkers := plan.ConcurrentFiles
	if totalFiles < numWorkers {
		numWorkers = totalFiles
	}

	utils.WorkerCountOverride = plan.WorkersPerFile
	defer func() {
		utils.WorkerCountOverride = 0
	}()

	maxConcurrentReaders := numWorkers
	maxConcurrentFinalizers := 2
	maxInFlightDetectors := maxConcurrentReaders + maxConcurrentFinalizers

	inFlightDetectorsSem := make(chan struct{}, maxInFlightDetectors)
	finalizeSem := make(chan struct{}, maxConcurrentFinalizers)

	var wg sync.WaitGroup
	var resultsWg sync.WaitGroup

	mergeResults := func(res []models.MLResult, detectorSeenIPs *engine.HyperLogLog) {
		seenMutex.Lock()
		seenIPs.Merge(detectorSeenIPs)
		seenMutex.Unlock()

		resultsMutex.Lock()
		for _, r := range res {
			if existing, ok := globalResultsMap[r.IP]; !ok || r.Probability > existing.Probability {
				globalResultsMap[r.IP] = r
			}
		}
		resultsMutex.Unlock()
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for job := range jobs {
				if !Silence {
					fmt.Printf("Processing file %d/%d: %s\n", job.Index+1, totalFiles, filepath.Base(job.Path))
				}
				ext := strings.ToLower(filepath.Ext(job.Path))
				var count int64
				var err error

				inFlightDetectorsSem <- struct{}{}

				if ext == ".pcap" {
					var pcapDetector *engine.PcapDetector
					pcapDetector, err = engine.NewPcapDetector(resolveModelPath(true))
					if err == nil {
						if cfg != nil {
							pcapDetector.Subnet = cfg.Subnet
						}
						count, err = ProcessPcapFile(job.Path, pcapDetector, scanner.StreamPCAP)
					}

					if err == nil {
						resultsWg.Add(1)
						go func(d *engine.PcapDetector) {
							defer resultsWg.Done()
							defer func() { <-inFlightDetectorsSem }()

							finalizeSem <- struct{}{}
							defer func() { <-finalizeSem }()

							res, _ := d.CalculateResults()
							mergeResults(res, d.SeenIPs)
						}(pcapDetector)
					} else {
						<-inFlightDetectorsSem
					}
				} else {
					var netflowDetector *engine.Detector
					netflowDetector, err = engine.NewDetector(resolveModelPath(false))
					if err == nil {
						if cfg != nil {
							netflowDetector.Subnet = cfg.Subnet
						}
						if ext == ".csv" {
							count, err = ProcessFile(job.Path, netflowDetector, scanner.StreamCSV)
						} else if ext == ".json" {
							count, err = ProcessFile(job.Path, netflowDetector, scanner.StreamJSON)
						} else if ext == ".ndjson" {
							count, err = ProcessFile(job.Path, netflowDetector, scanner.StreamNDJSON)
						}
					}

					if err == nil {
						resultsWg.Add(1)
						go func(d *engine.Detector) {
							defer resultsWg.Done()
							defer func() { <-inFlightDetectorsSem }()

							finalizeSem <- struct{}{}
							defer func() { <-finalizeSem }()

							res, _ := d.CalculateResults()
							mergeResults(res, d.SeenIPs)
						}(netflowDetector)
					} else {
						<-inFlightDetectorsSem
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
		}()
	}
	wg.Wait()
	resultsWg.Wait()

	var finalResults []models.MLResult
	for _, r := range globalResultsMap {
		finalResults = append(finalResults, r)
	}

	return finalResults, seenIPs.Estimate(), totalRecords.Load(), nil
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
