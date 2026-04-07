package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"goversion/config"
	"goversion/engine"
	"goversion/ingest"
	"goversion/output"
	"goversion/reporter"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	start := time.Now()

	appConfig := &config.AppConfig{}
	if err := appConfig.ParseArgs(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		return err
	}

	// Start CPU profile if flag is set
	if appConfig.CpuProfile != "" {
		f, err := os.Create(appConfig.CpuProfile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
		defer pprof.StopCPUProfile()
		defer f.Close()
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

	// Save memory profile if flag is set
	if appConfig.MemProfile != "" {
		f, err := os.Create(appConfig.MemProfile)
		if err != nil {
			return fmt.Errorf("could not create memory profile: %w", err)
		}
		defer f.Close()
		runtime.GC() // Get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("could not write memory profile: %w", err)
		}
	}

	return nil
}
