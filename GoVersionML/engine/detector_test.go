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

	results, _ := d.CalculateResults()

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
	d := &Detector{model: mock, maxProbs: make(map[uint32]float64)}

	// Case: All features are 0.0 to test sparsity logic
	stats := NewIPStats()
	stats.IP, _ = ParseIPv4("1.2.3.4")
	// ToMLVector naturally returns zeroes

	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		// D: Verify the SparseVector is empty for zero-inputs
		if len(input.Vectors[0]) != 0 {
			t.Errorf("Expected empty sparse vector, got length %d", len(input.Vectors[0]))
		}
		// Library returns float32
		val := float32(0.7)
		return mat.Matrix{Vectors: []*mat.Vector{{val}}}, nil
	}

	d.evaluateBatch([]*IPStats{stats})

	// FIXED: Use epsilon comparison to handle float32 -> float64 conversion drift
	const expected = 0.7

	const epsilon = 1e-7
	ipVal, _ := ParseIPv4("1.2.3.4")
	prob := d.maxProbs[ipVal]
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
		maxProbs:   make(map[uint32]float64),
	}

	// Setup two unique IPs in the aggregator via Update (hashing to the same partition)
	d.aggregator.Update(models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"})
	d.aggregator.Update(models.NetflowRecord{Src4Addr: "1.1.1.65", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"})

	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		// Return 2 vectors, simulate failure for the first by returning nil
		return mat.Matrix{Vectors: []*mat.Vector{nil, {0.9}}}, nil
	}

	results, _ := d.CalculateResults()

	// Verify we still got 1 result despite the nil logic skipping one
	if len(results) != 1 {
		t.Errorf("Expected 1 successful result after 1 nil vector, got %d", len(results))
	}
}

func TestDetector_ProcessRecord(t *testing.T) {
	d := &Detector{
		aggregator: NewAggregator(),
	}
	rec := models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"}

	d.ProcessRecord(rec)

	if d.TotalRecords != 1 {
		t.Errorf("TotalRecords not incremented: got %d", d.TotalRecords)
	}
}

func TestDetector_FormatResults_Threshold(t *testing.T) {
	d := &Detector{}
	ipBot, _ := ParseIPv4("1.1.1.1")
	ipBenign, _ := ParseIPv4("2.2.2.2")
	probs := map[uint32]float64{
		ipBot:    0.81,
		ipBenign: 0.49,
	}

	results := d.formatResults(probs)
	for _, res := range results {
		if res.IP == "1.1.1.1" && !res.IsBotnet {
			t.Error("0.81 should be marked as botnet")
		}
		if res.IP == "2.2.2.2" && res.IsBotnet {
			t.Error("0.49 should not be marked as botnet")
		}
	}
}

func TestDetector_TotalCount(t *testing.T) {
	d := &Detector{}
	d.TotalRecords = 42
	if d.TotalCount() != 42 {
		t.Errorf("Expected 42, got %d", d.TotalCount())
	}
}

func TestDetector_ProcessRecords(t *testing.T) {
	d := &Detector{
		aggregator: NewAggregator(),
	}
	records := []models.NetflowRecord{
		{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"},
		{Src4Addr: "2.2.2.2", First: "2026-03-17T12:05:00.000", Last: "2026-03-17T12:05:00.000"},
		{Src4Addr: "3.3.3.3", First: "invalid-time-stamp"},
	}
	d.ProcessRecords(records)

	if d.TotalCount() != 3 {
		t.Errorf("Expected 3, got %d", d.TotalCount())
	}
}

func TestDetector_updateMaxWindowAndFlush(t *testing.T) {
	mock := &MockModel{}
	d := &Detector{
		aggregator: NewAggregator(),
		model:      mock,
		maxProbs:   make(map[uint32]float64),
	}

	// Insert data into aggregator with a window.
	// 2026-03-17T12:00:00.000 is window 1773748800
	rec := models.NetflowRecord{Src4Addr: "1.1.1.1", First: "2026-03-17T12:00:00.000", Last: "2026-03-17T12:00:00.000"}
	d.ProcessRecord(rec)

	var evaluateCalled bool
	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		evaluateCalled = true
		return mat.Matrix{Vectors: []*mat.Vector{{0.99}}}, nil
	}

	// flushOldWindows flushes if key.Window < threshold
	// If win = 1773748800 + 400, threshold = win - 300 = 1773748800 + 100
	baseWin := int64(1773748800)
	d.updateMaxWindowAndFlush(baseWin + 400)

	if !evaluateCalled {
		t.Error("Expected evaluateBatch to be called via flushOldWindows")
	}

	if d.currentWindow.Load() != baseWin+400 {
		t.Errorf("Expected currentWindow to be updated, got %d", d.currentWindow.Load())
	}
}

type dummyError struct{}

func (e dummyError) Error() string { return "dummy error" }

func TestEvaluateBatch_ErrorHandling(t *testing.T) {
	mock := &MockModel{}
	d := &Detector{
		aggregator: NewAggregator(),
		model:      mock,
		maxProbs:   make(map[uint32]float64),
	}

	stats := NewIPStats()
	stats.IP, _ = ParseIPv4("1.2.3.4")

	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		return mat.Matrix{}, dummyError{}
	}

	// This should not panic
	d.evaluateBatch([]*IPStats{stats})

	if len(d.maxProbs) != 0 {
		t.Errorf("Expected maxProbs to be empty on error, got %d", len(d.maxProbs))
	}
}

func TestEvaluateBatch_MaxProbUpdate(t *testing.T) {
	mock := &MockModel{}
	d := &Detector{
		aggregator: NewAggregator(),
		model:      mock,
		maxProbs:   make(map[uint32]float64),
	}

	ipVal, _ := ParseIPv4("10.0.0.1")

	// First update with 0.5
	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		return mat.Matrix{Vectors: []*mat.Vector{{0.5}}}, nil
	}
	stats1 := NewIPStats()
	stats1.IP = ipVal
	d.evaluateBatch([]*IPStats{stats1})

	if d.maxProbs[ipVal] != 0.5 {
		t.Errorf("Expected 0.5, got %v", d.maxProbs[ipVal])
	}

	// Second update with 0.8 (should update)
	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		return mat.Matrix{Vectors: []*mat.Vector{{0.8}}}, nil
	}
	stats2 := NewIPStats()
	stats2.IP = ipVal
	d.evaluateBatch([]*IPStats{stats2})

	if math.Abs(d.maxProbs[ipVal]-float64(float32(0.8))) > 1e-6 {
		t.Errorf("Expected ~0.8, got %v", d.maxProbs[ipVal])
	}

	// Third update with 0.3 (should NOT update)
	mock.PredictFunc = func(input mat.SparseMatrix) (mat.Matrix, error) {
		return mat.Matrix{Vectors: []*mat.Vector{{0.3}}}, nil
	}
	stats3 := NewIPStats()
	stats3.IP = ipVal
	d.evaluateBatch([]*IPStats{stats3})

	if math.Abs(d.maxProbs[ipVal]-float64(float32(0.8))) > 1e-6 {
		t.Errorf("Expected ~0.8 after lower prob, got %v", d.maxProbs[ipVal])
	}
}
