package pipeline

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"goversion/JSONScanner"
	"goversion/NDJSONScanner"
	"goversion/config"
	"goversion/engine"
	"goversion/models"
)

func RunPipelineForInput(cfg *config.AppConfig) ([]models.MLResult, int64, error) {
	info, err := os.Stat(cfg.InputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat input path: %w", err)
	}

	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(cfg.InputPath))
		if ext == ".pcap" {
			return nil, 0, fmt.Errorf("pcap pipeline is not yet implemented")
		}
		if ext == ".ndjson" {
			return AnalyzeFile(cfg.InputPath, cfg.ModelPath, NDJSONScanner.StreamNetflowV2)
		}
		if ext == ".json" {
			return AnalyzeFile(cfg.InputPath, cfg.ModelPath, JSONScanner.StreamNetflow)
		}
		return nil, 0, fmt.Errorf("unsupported file extension: %s", ext)
	}

	var jsonFiles []string
	var ndjsonFiles []string

	err = filepath.WalkDir(cfg.InputPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".json" {
				jsonFiles = append(jsonFiles, path)
			} else if ext == ".ndjson" {
				ndjsonFiles = append(ndjsonFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("error walking directory: %w", err)
	}

	jsonCount := len(jsonFiles)
	ndjsonCount := len(ndjsonFiles)
	totalFiles := jsonCount + ndjsonCount

	if totalFiles == 0 {
		return nil, 0, fmt.Errorf("no .json or .ndjson files found in directory")
	}

	reader := bufio.NewReader(os.Stdin)
	if jsonCount > 0 && ndjsonCount == 0 {
		fmt.Printf("The following file type has been detected: json (%d files). Continue with json parsing? [y/N]: ", jsonCount)
	} else if ndjsonCount > 0 && jsonCount == 0 {
		fmt.Printf("The following file type has been detected: ndjson (%d files). Continue with ndjson parsing? [y/N]: ", ndjsonCount)
	} else {
		fmt.Printf("The following file types have been detected: json (%d files) ndjson (%d files).\n", jsonCount, ndjsonCount)
		fmt.Print("Continue parsing mixed file types (experimental)? [y/N]: ")
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, 0, fmt.Errorf("error reading response: %w", err)
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		return nil, 0, fmt.Errorf("parsing cancelled by user")
	}

	detector, err := engine.NewDetector(cfg.ModelPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}

	allFiles := append(jsonFiles, ndjsonFiles...)
	for i, file := range allFiles {
		ext := strings.ToLower(filepath.Ext(file))
		var stream StreamFn
		if ext == ".json" {
			stream = JSONScanner.StreamNetflow
		} else {
			stream = NDJSONScanner.StreamNetflowV2
		}

		fmt.Printf("Processing file %d/%d: %s\n", i+1, totalFiles, filepath.Base(file))
		_, err := ProcessFile(file, detector, stream)
		if err != nil {
			fmt.Printf("Error processing %s: %v\n", file, err)
			continue
		}
		
		detector.Flush()
		runtime.GC()
	}

	results := detector.CalculateResults()
	return results, detector.TotalCount(), nil
}
