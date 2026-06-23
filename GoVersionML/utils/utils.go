/*
Package utils provides concurrency planning and parameter tuning calculations
for the Pencilgon application.

It manages hardware CPU core auto-detection, recommended limits on parallel workers
per file to optimize pipeline performance, and concurrency plans for parsing multiple files.
*/
package utils

import "runtime"

var numCPU = runtime.NumCPU

var WorkerCountOverride int = 0

var ConfiguredConcurrentFiles int = 0
var ConfiguredWorkersPerFile int = 0

func OptimalWorkerCount() int {
	if WorkerCountOverride > 0 {
		return WorkerCountOverride
	}
	if ConfiguredWorkersPerFile > 0 {
		return ConfiguredWorkersPerFile
	}
	numWorkers := numCPU() / 4
	if numWorkers < 2 {
		numWorkers = 2
	}
	if numWorkers > 8 {
		numWorkers = 8
	}
	return numWorkers
}

type ConcurrencyPlan struct {
	ConcurrentFiles int
	WorkersPerFile  int
}

func GetConcurrencyPlan() ConcurrencyPlan {
	if ConfiguredConcurrentFiles > 0 && ConfiguredWorkersPerFile > 0 {
		return ConcurrencyPlan{
			ConcurrentFiles: ConfiguredConcurrentFiles,
			WorkersPerFile:  ConfiguredWorkersPerFile,
		}
	}
	return GetRecommendedPlan()
}

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

	cf := nc / 16
	if cf > 8 {
		cf = 8
	}
	if cf < 1 {
		cf = 1
	}
	return ConcurrencyPlan{ConcurrentFiles: cf, WorkersPerFile: 8}
}
