package main

import (
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

	appConfig, err := config.ParseFlags()
	if err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	out, cleanup, err := output.Setup(appConfig.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to setup output: %w", err)
	}
	defer cleanup()

	detector := engine.NewDetector(appConfig.ModelPath)
	fmt.Fprintf(out, "Scanning %s with XGBoost...\n", appConfig.NetflowPath)

	err = ingest.ProcessInput(appConfig.NetflowPath, detector.ProcessRecord)
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
