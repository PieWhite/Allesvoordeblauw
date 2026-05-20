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

// classifiedFiles groups discovered files by their supported type.
type classifiedFiles struct {
	json        []string
	ndjson      []string
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
		return routeSingleFile(cfg.InputPath, cfg.ModelPath)
	}

	return runDirectoryPipeline(cfg.InputPath, cfg.ModelPath)
}

// routeSingleFile dispatches a single file to the correct scanner based on extension.
func routeSingleFile(inputPath, modelPath string) ([]models.MLResult, int64, error) {
	ext := strings.ToLower(filepath.Ext(inputPath))

	switch ext {
	case ".pcap":
		return nil, 0, fmt.Errorf("pcap pipeline is not yet implemented")
	case ".ndjson":
		return AnalyzeFile(inputPath, modelPath, NDJSONScanner.StreamNetflowV2)
	case ".json":
		return AnalyzeFile(inputPath, modelPath, JSONScanner.StreamNetflow)
	default:
		return nil, 0, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

// runDirectoryPipeline orchestrates the full directory flow:
// classify → confirm → batch process.
func runDirectoryPipeline(dirPath, modelPath string) ([]models.MLResult, int64, error) {
	classified, err := classifyDirectory(dirPath)
	if err != nil {
		return nil, 0, fmt.Errorf("error walking directory: %w", err)
	}

	totalFiles := len(classified.json) + len(classified.ndjson)
	if totalFiles == 0 {
		return nil, 0, fmt.Errorf("no .json or .ndjson files found in directory")
	}

	if len(classified.unsupported) > 0 {
		fmt.Printf("Unsupported file types detected (%d files). These will be skipped.\n", len(classified.unsupported))
	}

	if err := confirmDirectoryParse(classified); err != nil {
		return nil, 0, err
	}

	return processBatch(classified, modelPath, totalFiles)
}

// classifyDirectory walks dirPath and groups every file by extension.
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

	switch {
	case jsonCount > 0 && ndjsonCount == 0:
		fmt.Printf("The following file type has been detected: json (%d files). Continue with json parsing? [y/N]: ", jsonCount)
	case ndjsonCount > 0 && jsonCount == 0:
		fmt.Printf("The following file type has been detected: ndjson (%d files). Continue with ndjson parsing? [y/N]: ", ndjsonCount)
	default:
		fmt.Printf("The following file types have been detected: json (%d files) ndjson (%d files).\n", jsonCount, ndjsonCount)
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

func processBatch(cf classifiedFiles, modelPath string, totalFiles int) ([]models.MLResult, int64, error) {
	detector, err := engine.NewDetector(modelPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed loading xgboost model: %w", err)
	}

	allFiles := append(cf.json, cf.ndjson...)
	for i, file := range allFiles {
		stream := streamFnFor(file)
		fmt.Printf("Processing file %d/%d: %s\n", i+1, totalFiles, filepath.Base(file))

		if _, err := ProcessFile(file, detector, stream); err != nil {
			fmt.Printf("Error processing %s: %v\n", file, err)
			continue
		}

		detector.Flush()
		runtime.GC()
	}

	results := detector.CalculateResults()
	return results, detector.TotalCount(), nil
}

func streamFnFor(path string) StreamFn {
	if strings.ToLower(filepath.Ext(path)) == ".json" {
		return JSONScanner.StreamNetflow
	}
	return NDJSONScanner.StreamNetflowV2
}
