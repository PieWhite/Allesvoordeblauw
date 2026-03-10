package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"goversion/config"
	"goversion/ingest"
	"goversion/output"
	"goversion/reporter"
)

func main() {
	start := time.Now()

	appConfig, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	out, cleanup, err := output.Setup(appConfig.OutputFile)
	if err != nil {
		log.Fatalf("Failed to setup output: %v", err)
	}
	defer cleanup()

	detector := NewDetector(appConfig.ModelPath)

	fmt.Fprintf(out, "Scanning %s with XGBoost ML Model...\n", appConfig.NetflowPath)

	err = ingest.ProcessInput(appConfig.NetflowPath, detector.ProcessRecord)
	if err != nil {
		log.Fatalf("Error scanning input file: %v", err)
	}

	// Get ML Results
	results := detector.Results()

	// Handle Presentation / Formatting
	reporter.PrintSummary(out, results, detector.TotalRecords, time.Since(start))

	if appConfig.OutputFile != "" {
		fmt.Printf("Results written to: %s\n", appConfig.OutputFile)
	}
}
