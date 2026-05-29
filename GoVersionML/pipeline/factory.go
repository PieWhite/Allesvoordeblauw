package pipeline

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
	"goversion/scanner"
)

// classifiedFiles groups discovered files by their supported type.
type classifiedFiles struct {
	json        []string
	ndjson      []string
	pcap        []string
	unsupported []string
}

// RunPipelineForInput is the main entry point. It delegates to single-file
// or directory processing based on the input path.
func RunPipelineForInput(cfg *config.AppConfig) ([]models.MLResult, int64, error) {
	info, err := os.Stat(cfg.InputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat input path: %w", err)
	}

	if !info.IsDir() {
		return routeSingleFile(cfg.InputPath)
	}

	return runDirectoryPipeline(cfg)
}

// routeSingleFile dispatches a single file to the correct scanner based on extension.
func routeSingleFile(inputPath string) ([]models.MLResult, int64, error) {
	ext := strings.ToLower(filepath.Ext(inputPath))

	switch ext {
	case ".pcap":
		resolved := resolveModelPath(true)
		return AnalyzePcapFile(inputPath, resolved, scanner.StreamPCAP)
	case ".ndjson":
		resolved := resolveModelPath(false)
		return AnalyzeFile(inputPath, resolved, scanner.StreamNDJSON)
	case ".json":
		resolved := resolveModelPath(false)
		return AnalyzeFile(inputPath, resolved, scanner.StreamJSON)
	default:
		return nil, 0, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

func runDirectoryPipeline(cfg *config.AppConfig) ([]models.MLResult, int64, error) {
	classified, err := classifyDirectory(cfg.InputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("error walking directory: %w", err)
	}

	totalFiles := len(classified.json) + len(classified.ndjson) + len(classified.pcap)
	if totalFiles == 0 {
		return nil, 0, fmt.Errorf("no .json, .ndjson or .pcap files found in directory")
	}

	if len(classified.unsupported) > 0 && !Silence {
		fmt.Printf("Unsupported file types detected (%d files). These will be skipped.\n", len(classified.unsupported))
	}

	if !cfg.SkipConfirm {
		if err := confirmDirectoryParse(classified); err != nil {
			return nil, 0, err
		}
	}

	return processBatch(classified, totalFiles)
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

	switch {
	case jsonCount > 0 && ndjsonCount == 0 && pcapCount == 0:
		fmt.Printf("The following file type has been detected: json (%d files). Continue with json parsing? [y/N]: ", jsonCount)
	case ndjsonCount > 0 && jsonCount == 0 && pcapCount == 0:
		fmt.Printf("The following file type has been detected: ndjson (%d files). Continue with ndjson parsing? [y/N]: ", ndjsonCount)
	case pcapCount > 0 && jsonCount == 0 && ndjsonCount == 0:
		fmt.Printf("The following file type has been detected: pcap (%d files). Continue with pcap parsing? [y/N]: ", pcapCount)
	default:
		fmt.Printf("The following file types have been detected: json (%d files) ndjson (%d files) pcap (%d files).\n", jsonCount, ndjsonCount, pcapCount)
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

func processBatch(cf classifiedFiles, totalFiles int) ([]models.MLResult, int64, error) {
	var netflowDetector *engine.Detector
	var pcapDetector *engine.PcapDetector
	var err error

	if len(cf.json) > 0 || len(cf.ndjson) > 0 {
		resolved := resolveModelPath(false)
		netflowDetector, err = engine.NewDetector(resolved)
		if err != nil {
			return nil, 0, fmt.Errorf("failed loading xgboost model for Netflow: %w", err)
		}
	}

	if len(cf.pcap) > 0 {
		resolved := resolveModelPath(true)
		pcapDetector, err = engine.NewPcapDetector(resolved)
		if err != nil {
			return nil, 0, fmt.Errorf("failed loading xgboost model for PCAP: %w", err)
		}
	}

	allFiles := make([]string, 0, totalFiles)
	allFiles = append(allFiles, cf.json...)
	allFiles = append(allFiles, cf.ndjson...)
	allFiles = append(allFiles, cf.pcap...)

	var totalRecords int64
	var allResults []models.MLResult

	for i, file := range allFiles {
		if !Silence {
			fmt.Printf("Processing file %d/%d: %s\n", i+1, totalFiles, filepath.Base(file))
		}
		ext := strings.ToLower(filepath.Ext(file))
		var err error

		if ext == ".pcap" {
			_, err = ProcessPcapFile(file, pcapDetector, scanner.StreamPCAP)
		} else if ext == ".json" {
			_, err = ProcessFile(file, netflowDetector, scanner.StreamJSON)
		} else if ext == ".ndjson" {
			_, err = ProcessFile(file, netflowDetector, scanner.StreamNDJSON)
		}

		if err != nil {
			if !Silence {
				fmt.Printf("Error processing %s: %v\n", file, err)
			}
			continue
		}

		if ext == ".pcap" {
			pcapDetector.Flush()
		} else {
			netflowDetector.Flush()
		}
		runtime.GC()
	}

	if netflowDetector != nil {
		allResults = append(allResults, netflowDetector.CalculateResults()...)
		totalRecords += netflowDetector.TotalCount()
	}
	if pcapDetector != nil {
		allResults = append(allResults, pcapDetector.CalculateResults()...)
		totalRecords += pcapDetector.TotalCount()
	}

	return allResults, totalRecords, nil
}

func streamFnFor(path string) StreamFn {
	if strings.ToLower(filepath.Ext(path)) == ".json" {
		return scanner.StreamJSON
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
