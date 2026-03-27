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
	fmt.Fprintf(out, "Scanning %s with XGBoost...\n", appConfig.NetflowPath)

	flowIngestor := ingest.NewIngestor()

	err = flowIngestor.ProcessInput(appConfig.NetflowPath, detector.ProcessRecords)
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
