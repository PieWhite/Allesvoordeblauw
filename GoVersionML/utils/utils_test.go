package utils

import (
	"runtime"
	"testing"
)

func TestOptimalWorkerCount(t *testing.T) {
	tests := []struct {
		name      string
		mockCores int
		expected  int
	}{
		{"Single Core Machine", 1, 2},
		{"Dual Core Machine", 2, 2},
		{"Quad Core Machine", 4, 2},
		{"Octa Core Machine", 8, 4},
		{"16 Core Machine", 16, 8},
		{"High-End 32 Core Machine", 32, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			originalNumCPU := numCPU
			defer func() { numCPU = originalNumCPU }()

			numCPU = func() int { return tt.mockCores }

			if got := OptimalWorkerCount(); got != tt.expected {
				t.Errorf("OptimalWorkerCount() = %v, want %v", got, tt.expected)
			}
		})
	}

	t.Run("Actual runtime execution", func(t *testing.T) {
		got := OptimalWorkerCount()
		if got < 2 {
			t.Errorf("Actual logic returned %v, must be at least 2", got)
		}

		expected := runtime.NumCPU() / 2
		if expected < 2 {
			expected = 2
		}

		if got != expected {
			t.Errorf("Actual execution mismatch: got %v, expected %v", got, expected)
		}
	})
}
