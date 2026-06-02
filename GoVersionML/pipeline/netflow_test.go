package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"goversion/config"
	"goversion/models"
)

// mockProcessor implements RecordProcessor for testing
type mockProcessor struct {
	recordsProcessed []models.NetflowRecord
	results          []models.MLResult
	total            int64
}

func (m *mockProcessor) ProcessRecords(records []models.NetflowRecord) {
	if m.recordsProcessed == nil {
		m.recordsProcessed = make([]models.NetflowRecord, 0)
	}
	m.recordsProcessed = append(m.recordsProcessed, records...)
	m.total += int64(len(records))
}

func (m *mockProcessor) CalculateResults() []models.MLResult {
	return m.results
}

func (m *mockProcessor) TotalCount() int64 {
	return m.total
}

func TestExecute(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		processor := &mockProcessor{
			results: []models.MLResult{{IP: "1.1.1.1", Probability: 0.9, IsBotnet: true}},
		}

		streamFn := func(r io.Reader, fn func([]models.NetflowRecord)) error {
			fn([]models.NetflowRecord{{First: "1"}})
			return nil
		}

		results, count, err := execute(nil, processor, streamFn)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if count != 1 {
			t.Errorf("expected count 1, got %d", count)
		}

		if len(results) != 1 || results[0].IP != "1.1.1.1" {
			t.Errorf("expected results to match processor, got %v", results)
		}

		if len(processor.recordsProcessed) != 1 || processor.recordsProcessed[0].First != "1" {
			t.Errorf("expected processor to have processed records, got %v", processor.recordsProcessed)
		}
	})

	t.Run("StreamError", func(t *testing.T) {
		processor := &mockProcessor{}

		expectedErr := errors.New("mock stream error")
		streamFn := func(r io.Reader, fn func([]models.NetflowRecord)) error {
			return expectedErr
		}

		results, count, err := execute(nil, processor, streamFn)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}

		if !errors.Is(err, expectedErr) && err.Error() != fmt.Sprintf("failed to stream netflow data: %v", expectedErr) {
			t.Errorf("expected specific stream error, got %v", err)
		}

		if results != nil {
			t.Errorf("expected nil results on error, got %v", results)
		}

		if count != 0 {
			t.Errorf("expected 0 count on error, got %d", count)
		}
	})

	t.Run("NilStream", func(t *testing.T) {
		processor := &mockProcessor{}
		_, _, err := execute(nil, processor, nil)
		if err == nil {
			t.Fatalf("expected error for nil stream, got nil")
		}
		if !strings.Contains(err.Error(), "stream function cannot be nil") {
			t.Errorf("expected 'stream function cannot be nil' error, got: %v", err)
		}
	})
}

func TestProcessFile(t *testing.T) {
	t.Run("NilStream", func(t *testing.T) {
		processor := &mockProcessor{}
		_, err := ProcessFile("nonexistent_input.json", processor, nil)
		if err == nil {
			t.Fatalf("expected error for nil stream, got nil")
		}
		if !strings.Contains(err.Error(), "stream function cannot be nil") {
			t.Errorf("expected 'stream function cannot be nil' error, got: %v", err)
		}
	})

	t.Run("OpenFailure", func(t *testing.T) {
		processor := &mockProcessor{}
		streamFn := func(r io.Reader, fn func([]models.NetflowRecord)) error {
			return nil
		}

		_, err := ProcessFile("nonexistent_input.json", processor, streamFn)
		if err == nil {
			t.Fatalf("expected error for missing input file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("expected file open error, got: %v", err)
		}
	})

	t.Run("StreamError", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "process_file_stream_error_*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		processor := &mockProcessor{}
		expectedErr := errors.New("mock stream error")
		streamFn := func(r io.Reader, fn func([]models.NetflowRecord)) error {
			return expectedErr
		}

		count, err := ProcessFile(tempFile.Name(), processor, streamFn)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected specific stream error, got %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 count on error, got %d", count)
		}
	})

	t.Run("Success", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "process_file_success_*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		if _, err := tempFile.WriteString(`[{"first":"1"},{"first":"2"}]`); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		tempFile.Close()

		processor := &mockProcessor{}
		streamFn := func(r io.Reader, fn func([]models.NetflowRecord)) error {
			var records []models.NetflowRecord
			if err := json.NewDecoder(r).Decode(&records); err != nil {
				return err
			}
			fn(records)
			return nil
		}

		count, err := ProcessFile(tempFile.Name(), processor, streamFn)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if count != 2 {
			t.Errorf("expected count 2, got %d", count)
		}
		if len(processor.recordsProcessed) != 2 {
			t.Errorf("expected processor to process 2 records, got %d", len(processor.recordsProcessed))
		}
		if processor.recordsProcessed[0].First != "1" || processor.recordsProcessed[1].First != "2" {
			t.Errorf("expected processed records [1,2], got %+v", processor.recordsProcessed)
		}
	})
}

func TestAnalyzeFile(t *testing.T) {
	validModel := "../Xgboost/botnet_xgboost.json"

	mockScanner := func(r io.Reader, fn func([]models.NetflowRecord)) error {
		return nil
	}

	t.Run("InvalidModelPath", func(t *testing.T) {
		_, _, err := AnalyzeFile(&config.AppConfig{InputPath: "dummy.json"}, "invalid/path/to/model.json", mockScanner)
		if err == nil {
			t.Fatalf("expected error for invalid model path, got nil")
		}
	})

	t.Run("InvalidInputPath", func(t *testing.T) {
		// Valid model, but invalid input file
		_, _, err := AnalyzeFile(&config.AppConfig{InputPath: "nonexistent_input.json"}, validModel, mockScanner)
		if err == nil {
			t.Fatalf("expected error for missing input file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("expected file open error, got: %v", err)
		}
	})

	t.Run("ValidFileAndModel", func(t *testing.T) {
		// Create a temporary input file
		tempFile, err := os.CreateTemp("", "test_input_*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())

		// We can just write an empty JSON array or a small record
		_, err = tempFile.WriteString(`{"first": "2026-05-02T15:04:05.000", "last": "2026-05-02T15:05:05.000", "src4_addr": "1.2.3.4"}`)
		if err != nil {
			t.Fatalf("failed to write to temp file: %v", err)
		}
		tempFile.Close()

		// Test success execution
		// Note: since this does actual ML inference setup, it may return some empty result or an error based on the ML engine if it expects specific format
		_, _, err = AnalyzeFile(&config.AppConfig{InputPath: tempFile.Name()}, validModel, mockScanner)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("NilStream", func(t *testing.T) {
		_, _, err := AnalyzeFile(&config.AppConfig{InputPath: "dummy.json"}, validModel, nil)
		if err == nil {
			t.Fatalf("expected error for nil stream, got nil")
		}
		if !strings.Contains(err.Error(), "stream function cannot be nil") {
			t.Errorf("expected 'stream function cannot be nil' error, got: %v", err)
		}
	})
}
