package utils

import (
	"runtime"
	"testing"
)

func TestOptimalWorkerCount(t *testing.T) {
	// Table-driven tests for various CPU scenarios
	tests := []struct {
		name      string
		mockCores int
		expected  int
	}{
		{"Single Core Machine", 1, 2},
		{"Dual Core Machine", 2, 2},
		{"Quad Core Machine", 4, 3},
		{"Octa Core Machine", 8, 7},
		{"16 Core Machine", 16, 15},
		{"High-End 32 Core Machine", 32, 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the original function and defer its restoration
			originalNumCPU := numCPU
			defer func() { numCPU = originalNumCPU }()

			// Inject mock
			numCPU = func() int { return tt.mockCores }

			if got := OptimalWorkerCount(); got != tt.expected {
				t.Errorf("OptimalWorkerCount() = %v, want %v", got, tt.expected)
			}
		})
	}

	// Unmocked test to verify real-world behavior bounds
	t.Run("Actual runtime execution", func(t *testing.T) {
		got := OptimalWorkerCount()
		if got < 2 {
			t.Errorf("Actual logic returned %v, must be at least 2", got)
		}

		expected := runtime.NumCPU() - 1 // the exact same logic
		if expected < 2 {
			expected = 2
		}

		if got != expected {
			t.Errorf("Actual execution mismatch: got %v, expected %v", got, expected)
		}
	})
}
