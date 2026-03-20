package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"goversion/config"
	"goversion/engine"
	"goversion/ingest"
	"goversion/output"
	"goversion/reporter"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	start := time.Now()

	appConfig := &config.AppConfig{}
	if err := appConfig.ParseArgs(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		return err
	}

	out, cleanup, err := output.Setup(appConfig.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to setup output: %w", err)
	}
	defer cleanup()

	detector, err := engine.NewDetector(appConfig.ModelPath)
	if err != nil {
		return fmt.Errorf("Failed loading xgboost model %w", err)
	}

	selectedFormat := ingest.InputFormat(appConfig.InputFormat)
	if appConfig.InputFormat == "auto" {
		detected, detectErr := ingest.DetectInputFormatByPath(appConfig.NetflowPath)
		if detectErr != nil {
			return detectErr
		}
		selectedFormat = detected
	}

	fmt.Fprintf(out, "Detected input format: %s\n", selectedFormat)
	fmt.Fprintf(out, "Scanning %s with XGBoost...\n", appConfig.NetflowPath)

	flowIngestor := &ingest.Ingestor{
		NetflowScanner: &ingest.JSONScanner{},
		InputFormat:    selectedFormat,
	}

	err = flowIngestor.ProcessInput(appConfig.NetflowPath, detector.ProcessRecord)
	if err != nil {
		return fmt.Errorf("scanning input file: %w", err)
	}

	results := detector.CalculateResults()
	reporter.PrintSummary(out, results, detector.TotalRecords, time.Since(start))

	if appConfig.OutputFile != "" {
		fmt.Printf("Results written to: %s\n", appConfig.OutputFile)
	}

	return nil
}
