package utils

import "runtime"

var numCPU = runtime.NumCPU

// WorkerCountOverride allows overriding the optimal worker count calculation
var WorkerCountOverride int = 0

// User-configured values (0 means use auto-detected defaults)
var ConfiguredConcurrentFiles int = 0
var ConfiguredWorkersPerFile int = 0

// OptimalWorkerCount returns the optimal worker count for parsing a single file.
func OptimalWorkerCount() int {
	if WorkerCountOverride > 0 {
		return WorkerCountOverride
	}
	if ConfiguredWorkersPerFile > 0 {
		return ConfiguredWorkersPerFile
	}
	numWorkers := numCPU() / 4 // Align with physical cores and pipeline overhead
	if numWorkers < 2 {
		numWorkers = 2
	}
	// Cap at 8 to prevent excessive scheduling overhead on high-core-count machines
	if numWorkers > 8 {
		numWorkers = 8
	}
	return numWorkers
}

// ConcurrencyPlan holds the planned concurrency parameters
type ConcurrencyPlan struct {
	ConcurrentFiles int
	WorkersPerFile  int
}

// GetConcurrencyPlan determines the optimal layout of directory-level and file-level parallelism
func GetConcurrencyPlan() ConcurrencyPlan {
	if ConfiguredConcurrentFiles > 0 && ConfiguredWorkersPerFile > 0 {
		return ConcurrencyPlan{
			ConcurrentFiles: ConfiguredConcurrentFiles,
			WorkersPerFile:  ConfiguredWorkersPerFile,
		}
	}
	return GetRecommendedPlan()
}

// GetRecommendedPlan returns the recommended concurrency plan without user overrides
func GetRecommendedPlan() ConcurrencyPlan {
	nc := numCPU()
	if nc <= 4 {
		return ConcurrencyPlan{ConcurrentFiles: 1, WorkersPerFile: 2}
	}
	if nc <= 8 {
		return ConcurrencyPlan{ConcurrentFiles: 2, WorkersPerFile: 2}
	}
	if nc <= 16 {
		return ConcurrencyPlan{ConcurrentFiles: 2, WorkersPerFile: 2}
	}
	if nc <= 32 {
		return ConcurrencyPlan{ConcurrentFiles: 4, WorkersPerFile: 4}
	}
	if nc <= 64 {
		return ConcurrencyPlan{ConcurrentFiles: 4, WorkersPerFile: 8}
	}

	// For massive machines (e.g. 128 threads), cap workers per file at 8
	// and concurrent files at 8 to avoid lock/disk contention.
	cf := nc / 16
	if cf > 8 {
		cf = 8
	}
	if cf < 1 {
		cf = 1
	}
	return ConcurrencyPlan{ConcurrentFiles: cf, WorkersPerFile: 8}
}
