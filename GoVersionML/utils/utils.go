package utils

import "runtime"

// numCPU is assigned here so it can be mocked in unit tests
var numCPU = runtime.NumCPU

func OptimalWorkerCount() int {
	numWorkers := numCPU() - 1 // Leave 1 CPU free
	if numWorkers < 2 {
		numWorkers = 2
	}
	return numWorkers
}
