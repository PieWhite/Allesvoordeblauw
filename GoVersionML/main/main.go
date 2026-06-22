/*
Package main serves as the primary entry point for the Pencilgon botnet detection CLI tool.
It handles runtime setup, configuration validation, profiling execution, and pipelines processing.
*/
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
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	start := time.Now()

	appConfig := &config.AppConfig{}
	if err := appConfig.ParseArgs(args); err != nil {
		return err
	}

	if appConfig.CPUProfile != "" {
		f, err := os.Create(appConfig.CPUProfile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	out, cleanup, err := output.Setup(appConfig.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to setup output: %w", err)
	}
	defer cleanup()

	fmt.Fprintf(out, "Scanning %s ...\n", appConfig.InputPath)

	results, totalUnique, totalRecords, err := pipeline.RunPipelineForInput(appConfig)
	if err != nil {
		return fmt.Errorf("failed to process input pipeline for %q: %w", appConfig.InputPath, err)
	}

	reporter.PrintSummary(out, results, totalUnique, totalRecords, time.Since(start))

	if appConfig.OutputFile != "" {
		fmt.Printf("Results written to: %s\n", appConfig.OutputFile)
	}

	if appConfig.MemProfile != "" {
		f, err := os.Create(appConfig.MemProfile)
		if err != nil {
			return fmt.Errorf("could not create memory profile: %w", err)
		}
		defer f.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("could not write memory profile: %w", err)
		}
	}

	return nil
}
