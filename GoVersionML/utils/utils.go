package utils

import "runtime"

var numCPU = runtime.NumCPU

func OptimalWorkerCount() int {
	numWorkers := numCPU() / 2 // Laat ruimte over voor andere taken "CPU Thrashing"
	if numWorkers < 2 {
		numWorkers = 2
	}
	return numWorkers
}
