package pipeline

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"goversion/config"
	"goversion/models"
)

// mockPcapProcessor implements PcapRecordProcessor for testing
type mockPcapProcessor struct {
	recordsProcessed []models.PcapRecord
	results          []models.MLResult
	total            int64
}

func (m *mockPcapProcessor) ProcessPcapRecords(records []models.PcapRecord) {
	if m.recordsProcessed == nil {
		m.recordsProcessed = make([]models.PcapRecord, 0)
	}
	m.recordsProcessed = append(m.recordsProcessed, records...)
	m.total += int64(len(records))
}

func (m *mockPcapProcessor) CalculateResults() ([]models.MLResult, int) {
	return m.results, len(m.results)
}

func (m *mockPcapProcessor) TotalCount() int64 {
	return m.total
}

func TestProcessPcapFile(t *testing.T) {
	t.Run("NilStream", func(t *testing.T) {
		processor := &mockPcapProcessor{}
		_, err := ProcessPcapFile("nonexistent_input.pcap", processor, nil)
		if err == nil {
			t.Fatalf("expected error for nil stream, got nil")
		}
		if !strings.Contains(err.Error(), "stream function cannot be nil") {
			t.Errorf("expected 'stream function cannot be nil' error, got: %v", err)
		}
	})

	t.Run("OpenFailure", func(t *testing.T) {
		processor := &mockPcapProcessor{}
		streamFn := func(r io.Reader, fn func([]models.PcapRecord)) error {
			return nil
		}

		_, err := ProcessPcapFile("nonexistent_input.pcap", processor, streamFn)
		if err == nil {
			t.Fatalf("expected error for missing input file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("expected file open error, got: %v", err)
		}
	})

	t.Run("StreamError", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "process_pcap_file_stream_error_*.pcap")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		processor := &mockPcapProcessor{}
		expectedErr := errors.New("mock stream error")
		streamFn := func(r io.Reader, fn func([]models.PcapRecord)) error {
			return expectedErr
		}

		count, err := ProcessPcapFile(tempFile.Name(), processor, streamFn)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) && !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Errorf("expected specific stream error, got %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 count on error, got %d", count)
		}
	})

	t.Run("Success", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "process_pcap_file_success_*.pcap")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		processor := &mockPcapProcessor{}
		streamFn := func(r io.Reader, fn func([]models.PcapRecord)) error {
			fn([]models.PcapRecord{
				{SrcIP: "1.1.1.1", DstIP: "2.2.2.2"},
				{SrcIP: "3.3.3.3", DstIP: "4.4.4.4"},
			})
			return nil
		}

		count, err := ProcessPcapFile(tempFile.Name(), processor, streamFn)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if count != 2 {
			t.Errorf("expected count 2, got %d", count)
		}
		if len(processor.recordsProcessed) != 2 {
			t.Errorf("expected processor to process 2 records, got %d", len(processor.recordsProcessed))
		}
		if processor.recordsProcessed[0].SrcIP != "1.1.1.1" || processor.recordsProcessed[1].SrcIP != "3.3.3.3" {
			t.Errorf("expected processed records [1.1.1.1, 3.3.3.3], got %+v", processor.recordsProcessed)
		}
	})
}

func TestAnalyzePcapFile(t *testing.T) {
	validModel := "../Xgboost/pcap_xgboost.json"

	mockScanner := func(r io.Reader, fn func([]models.PcapRecord)) error {
		return nil
	}

	t.Run("InvalidModelPath", func(t *testing.T) {
		cfg := &config.AppConfig{InputPath: "dummy.pcap"}
		_, _, _, err := AnalyzePcapFile(cfg, "invalid/path/to/model.json", mockScanner)
		if err == nil {
			t.Fatalf("expected error for invalid model path, got nil")
		}
	})

	t.Run("InvalidInputPath", func(t *testing.T) {
		cfg := &config.AppConfig{InputPath: "nonexistent_input.pcap"}
		_, _, _, err := AnalyzePcapFile(cfg, validModel, mockScanner)
		if err == nil {
			t.Fatalf("expected error for missing input file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("expected file open error, got: %v", err)
		}
	})

	t.Run("ValidFileAndModel", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "test_input_*.pcap")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		cfg := &config.AppConfig{InputPath: tempFile.Name()}
		_, _, _, err = AnalyzePcapFile(cfg, validModel, mockScanner)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}
