package engine

import (
	"math"
	"testing"

	"goversion/models"

	"github.com/Elvenson/xgboost-go/mat"
)

// --- Mocks ---

type MockModel struct {
	PredictFunc func(input mat.SparseMatrix) (mat.Matrix, error)
}

func (m *MockModel) PredictProba(input mat.SparseMatrix) (mat.Matrix, error) {
	return m.PredictFunc(input)
}

// --- Implementation of A, C, and D ---

// TestDetector_CalculateResults_Empty handles Scenario A:
// Checks if calculating results before processing data works gracefully.
func TestDetector_CalculateResults_Empty(t *testing.T) {
	d := &Detector{
		aggregator: NewAggregator(),
		model:      &MockModel{},
	}

	results := d.CalculateResults()

	if results == nil {
		t.Fatal("Expected an empty slice, got nil")
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty aggregator, got %d", len(results))
	}
}

// TestNewDetector_MockInitialization handles Scenario C:
// Mocks the constructor's error path for a missing file.
func TestNewDetector_MockInitialization(t *testing.T) {
	t.Run("Invalid Path Error", func(t *testing.T) {
		d, err := NewDetector("invalid/path/to/model.json")
		if err == nil {
			t.Error("Expected error for invalid model path, got nil")
		}
		if d != nil {
			t.Error("Detector should be nil on error")
		}
	})
}

// TestEvaluateBatch_SparseVectorOptimization handles Scenario D:
// Verifies sparse matrix construction and handles float precision.
func TestEvaluateBatch_SparseVectorOptimization(t *testing.T) {
	mock := &MockModel{}
	d := &Detector{model: mock, maxProbs: make(map[string]float64)}

	// Case: All features are 0.0 to test sparsity logic
	stats := NewIPStats()
	stats.IP = "1.2.3.4"
	// ToMLVector naturally returns zeroes

	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		// D: Verify the SparseVector is empty for zero-inputs
		if len(input.Vectors[0]) != 0 {
			t.Errorf("Expected empty sparse vector, got length %d", len(input.Vectors[0]))
		}
		// Library returns float32
		val := float32(0.1)
		return mat.Matrix{Vectors: []*mat.Vector{{val}}}, nil
	}

	d.evaluateBatch([]*IPStats{stats})

	// FIXED: Use epsilon comparison to handle float32 -> float64 conversion drift
	const expected = 0.1
	const epsilon = 1e-7
	prob := d.maxProbs["1.2.3.4"]
	if math.Abs(prob-expected) > epsilon {
		t.Errorf("Expected prob ~%v, got %v", expected, prob)
	}
}

// TestCalculateResults_LoggingAndContinue covers the specific branch:
// Skipping missing/nil vectors from batch prediction results
func TestCalculateResults_LoggingAndContinue(t *testing.T) {
	mock := &MockModel{}
	d := &Detector{
		aggregator: NewAggregator(),
		model:      mock,
		maxProbs:   make(map[string]float64),
	}

	// Setup two unique IPs in the aggregator via Update
	d.aggregator.Update(models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000"})
	d.aggregator.Update(models.NetflowRecord{Src4Addr: "2.2.2.2", First: "2026-03-17T12:00:00.000"})

	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		// Return 2 vectors, simulate failure for the first by returning nil
		return mat.Matrix{Vectors: []*mat.Vector{nil, {0.9}}}, nil
	}

	results := d.CalculateResults()

	// Verify we still got 1 result despite the nil logic skipping one
	if len(results) != 1 {
		t.Errorf("Expected 1 successful result after 1 nil vector, got %d", len(results))
	}
}

func TestDetector_ProcessRecord(t *testing.T) {
	d := &Detector{
		aggregator: NewAggregator(),
	}
	rec := models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000"}

	d.ProcessRecord(rec)

	if d.TotalRecords != 1 {
		t.Errorf("TotalRecords not incremented: got %d", d.TotalRecords)
	}
}

func TestDetector_FormatResults_Threshold(t *testing.T) {
	d := &Detector{}
	probs := map[string]float64{
		"bot":    0.51,
		"benign": 0.49,
	}

	results := d.formatResults(probs)
	for _, res := range results {
		if res.IP == "bot" && !res.IsBotnet {
			t.Error("0.51 should be marked as botnet")
		}
		if res.IP == "benign" && res.IsBotnet {
			t.Error("0.49 should not be marked as botnet")
		}
	}
}
