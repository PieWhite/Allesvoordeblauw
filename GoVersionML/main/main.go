package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"goversion/config"
	"goversion/output"
	"goversion/pipeline"
	"goversion/reporter"
	"goversion/tui"
)

func main() {
	if len(os.Args) == 1 {
		_, err := tui.Start()
		if err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
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

	fmt.Fprintf(out, "Scanning %s ...\n", appConfig.InputPath)

	results, totalRecords, err := pipeline.RunPipelineForInput(appConfig)
	if err != nil {
		return fmt.Errorf("failed to process input pipeline for %q: %w", appConfig.InputPath, err)
	}

	reporter.PrintSummary(out, results, totalRecords, time.Since(start))

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
