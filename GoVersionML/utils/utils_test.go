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
		{"Octa Core Machine", 8, 2},
		{"16 Core Machine", 16, 4},
		{"High-End 32 Core Machine", 32, 8},
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
		if got > 8 {
			t.Errorf("Actual logic returned %v, must be capped at 8", got)
		}

		expected := runtime.NumCPU() / 4
		if expected < 2 {
			expected = 2
		}
		if expected > 8 {
			expected = 8
		}

		if got != expected {
			t.Errorf("Actual execution mismatch: got %v, expected %v", got, expected)
		}
	})

	t.Run("GetConcurrencyPlan tests", func(t *testing.T) {
		plans := []struct {
			cores     int
			wantFiles int
			wantWork  int
		}{
			{4, 1, 2},
			{8, 2, 2},
			{16, 2, 2},
			{32, 4, 4},
			{64, 4, 8},
			{128, 8, 8},
		}

		originalNumCPU := numCPU
		defer func() { numCPU = originalNumCPU }()

		for _, p := range plans {
			numCPU = func() int { return p.cores }
			plan := GetConcurrencyPlan()
			if plan.ConcurrentFiles != p.wantFiles || plan.WorkersPerFile != p.wantWork {
				t.Errorf("Plan for %d cores: got (%d, %d), want (%d, %d)", p.cores, plan.ConcurrentFiles, plan.WorkersPerFile, p.wantFiles, p.wantWork)
			}
		}
	})
}
