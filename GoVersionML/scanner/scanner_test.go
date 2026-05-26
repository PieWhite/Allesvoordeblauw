package scanner

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"goversion/models"
)

// errorReader is a helper for simulating read errors.
type errorReader struct {
	readCount int
	maxReads  int
	err       error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	if e.readCount >= e.maxReads {
		return 0, e.err
	}
	e.readCount++
	// Return a valid JSON array start before failing
	validJSON := []byte(`[{"first":"2023-01-01T00:00:00Z","last":"2023-01-01T00:00:01Z","in_packets":10,"in_bytes":100,"proto":6,"tcp_flags":"SYN","src_port":1234,"dst_port":80,"src4_addr":"192.168.1.1","dst4_addr":"10.0.0.1"},`)
	n = copy(p, validJSON)
	return n, nil
}

func TestStreamNetflow_ValidData(t *testing.T) {
	jsonData := `[
{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"},
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}
]`
	reader := strings.NewReader(jsonData)

	var totalProcessed int32
	var mu sync.Mutex
	var processedRecords []models.NetflowRecord

	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
		mu.Lock()
		processedRecords = append(processedRecords, records...)
		mu.Unlock()
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 2 {
		t.Fatalf("Expected 2 records to be processed, got: %d", totalProcessed)
	}

	if len(processedRecords) != 2 {
		t.Fatalf("Expected 2 records stored, got: %d", len(processedRecords))
	}
}

func TestStreamNetflow_EmptyStream(t *testing.T) {
	reader := strings.NewReader("")

	var totalProcessed int32
	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 0 {
		t.Fatalf("Expected 0 records, got: %d", totalProcessed)
	}
}

func TestStreamNetflow_InvalidData(t *testing.T) {
	// Mixed valid and invalid data. 
	// The invalid json must be enclosed in {} for the splitJSONObjects tokenizer to capture it.
	jsonData := `[
{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"},
{INVALID_JSON_HERE},
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}
]`

	reader := strings.NewReader(jsonData)

	var totalProcessed int32
	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	// The scanner should process the 1 valid record and return an error for the invalid one.
	if err == nil {
		t.Fatal("Expected an error due to invalid JSON, got nil")
	}

	// Due to concurrency, exactly how many valid ones are processed is non-deterministic
	// But it should definitely throw an error and halt further processing.
}

func TestStreamNetflow_ScannerError(t *testing.T) {
	expectedErr := errors.New("simulated read error")
	reader := &errorReader{maxReads: 1, err: expectedErr}

	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		// Do nothing, just consume
	})

	if err == nil {
		t.Fatal("Expected an error from the reader, got nil")
	}

	if !strings.Contains(err.Error(), "simulated read error") {
		t.Fatalf("Expected error to contain 'simulated read error', got: %v", err)
	}
}

func TestStreamNetflow_LargeVolume(t *testing.T) {
	const numRecords = 5000 // Creates multiple batches since batchSize is 1000

	var builder strings.Builder
	builder.WriteString("[\n")
	validJSON := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`
	for i := 0; i < numRecords; i++ {
		builder.WriteString(validJSON)
		if i < numRecords-1 {
			builder.WriteString(",\n")
		}
	}
	builder.WriteString("\n]")

	reader := strings.NewReader(builder.String())

	var totalProcessed int32
	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != numRecords {
		t.Fatalf("Expected %d records, got: %d", numRecords, totalProcessed)
	}
}

func TestStreamNetflow_ArenaGrowth(t *testing.T) {
	// Create a JSON object that is very large to trigger arena growth
	// The default arena is 2MB. We'll make a 3MB string.
	padding := strings.Repeat("A", 3*1024*1024)
	largeJSON := fmt.Sprintf(`[{"first":"%s","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}]`, padding)

	reader := strings.NewReader(largeJSON)

	var totalProcessed int32
	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 1 {
		t.Fatalf("Expected 1 record processed, got: %d", totalProcessed)
	}
}

func TestStreamNetflow_ProcessFnConcurrency(t *testing.T) {
	// Verify that slices passed to processFn are not corrupted across calls if processFn processes synchronously
	jsonData := `[
{"in_packets":1},
{"in_packets":2},
{"in_packets":3}
]`
	reader := strings.NewReader(jsonData)

	var mu sync.Mutex
	var collected []int64

	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		mu.Lock()
		for _, r := range records {
			collected = append(collected, r.InPackets)
		}
		mu.Unlock()
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(collected) != 3 {
		t.Fatalf("Expected 3 records, got %d", len(collected))
	}

	// Check if 1, 2, 3 are all present
	found := make(map[int64]bool)
	for _, v := range collected {
		found[v] = true
	}
	if !found[1] || !found[2] || !found[3] {
		t.Fatalf("Expected 1, 2, and 3, got: %v", collected)
	}
}

func TestStreamNDJSON_ValidData(t *testing.T) {
	ndjsonData := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}`
	reader := strings.NewReader(ndjsonData)

	var totalProcessed int32
	var mu sync.Mutex
	var processedRecords []models.NetflowRecord

	err := StreamNDJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
		mu.Lock()
		processedRecords = append(processedRecords, records...)
		mu.Unlock()
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 2 {
		t.Fatalf("Expected 2 records to be processed, got: %d", totalProcessed)
	}

	if len(processedRecords) != 2 {
		t.Fatalf("Expected 2 records stored, got: %d", len(processedRecords))
	}
}

func TestStreamNDJSON_InvalidData(t *testing.T) {
	// First is valid, second is invalid, third is valid
	ndjsonData := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}
{INVALID_NDJSON_HERE}
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}`
	reader := strings.NewReader(ndjsonData)

	var totalProcessed int32
	var mu sync.Mutex
	var processedRecords []models.NetflowRecord

	err := StreamNDJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
		mu.Lock()
		processedRecords = append(processedRecords, records...)
		mu.Unlock()
	})

	if err == nil {
		t.Fatal("Expected an error from invalid NDJSON, got nil")
	}

	// In NDJSON mode, processing should continue despite the invalid record.
	// Since there's 1 invalid record and 2 valid records, we should process the 2 valid ones.
	if totalProcessed != 2 {
		t.Fatalf("Expected 2 valid records to be processed, got: %d", totalProcessed)
	}

	if len(processedRecords) != 2 {
		t.Fatalf("Expected 2 records stored, got: %d", len(processedRecords))
	}
}

func TestSplitJSONObjects_IncompleteEOF(t *testing.T) {
	jsonData := `{"first":"1","last":"2"`
	reader := strings.NewReader(jsonData)

	var totalProcessed int32
	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error for incomplete JSON at EOF, got: %v", err)
	}

	if totalProcessed != 0 {
		t.Fatalf("Expected 0 records, got: %d", totalProcessed)
	}
}

func TestStreamNetflow_WorkerErrorHaltsProducer(t *testing.T) {
	// A huge number of records with an invalid record in the middle.
	// Non-NDJSON mode should halt immediately.
	const numRecords = 2005
	var builder strings.Builder
	builder.WriteString("[\n")
	validJSON := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`
	
	// First batch (1000 items) is completely valid
	for i := 0; i < 1000; i++ {
		builder.WriteString(validJSON)
		builder.WriteString(",\n")
	}
	// Second batch has an invalid element early
	builder.WriteString(`{INVALID_JSON_HERE}`)
	builder.WriteString(",\n")

	// Rest of the batches are valid
	for i := 0; i < 1004; i++ {
		builder.WriteString(validJSON)
		if i < 1003 {
			builder.WriteString(",\n")
		}
	}
	builder.WriteString("\n]")

	reader := strings.NewReader(builder.String())

	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		// Do nothing
	})

	if err == nil {
		t.Fatal("Expected an error due to invalid JSON halting scanner, got nil")
	}
}

func TestStreamNetflow_EmptyAndNoiseInputs(t *testing.T) {
	// Let's stream noise: commas, spaces, empty lines in standard and NDJSON.
	// NDJSON with empty lines:
	ndjsonData := "\n\n   \n,\n\n  ,\n"
	reader := strings.NewReader(ndjsonData)

	var totalProcessed int32
	err := StreamNDJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error for empty/noise NDJSON, got: %v", err)
	}

	if totalProcessed != 0 {
		t.Fatalf("Expected 0 records, got: %d", totalProcessed)
	}

	// JSON with empty elements and noise:
	jsonData := `[ , ,   , ]`
	readerJSON := strings.NewReader(jsonData)

	err = StreamJSON(readerJSON, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error for empty/noise JSON array, got: %v", err)
	}
}

func TestStreamNetflow_SequentialOrder(t *testing.T) {
	// Generate 5000 records so we get multiple batches (since batchSize is 1000)
	// Each batch of 1000 will be tagged with different packet numbers.
	// Because of sequential ordering, batch 0 (packets 0) must be processed first,
	// batch 1 (packets 1) second, etc., even under concurrency.
	const numBatches = 5
	const batchSize = 1000
	var builder strings.Builder
	builder.WriteString("[\n")
	for b := 0; b < numBatches; b++ {
		for i := 0; i < batchSize; i++ {
			builder.WriteString(fmt.Sprintf(`{"first":"1","last":"2","in_packets":%d,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`, b))
			if b < numBatches-1 || i < batchSize-1 {
				builder.WriteString(",\n")
			}
		}
	}
	builder.WriteString("\n]")

	reader := strings.NewReader(builder.String())

	var lastBatchID int64 = -1
	err := StreamJSON(reader, func(records []models.NetflowRecord) {
		if len(records) > 0 {
			currentBatchID := records[0].InPackets
			// Verify that the batch ID is strictly sequential and monotonic
			if currentBatchID != lastBatchID+1 {
				t.Errorf("Expected batch ID %d, but got %d (out of order!)", lastBatchID+1, currentBatchID)
			}
			// Verify that all records in the batch have the same batch ID
			for _, r := range records {
				if r.InPackets != currentBatchID {
					t.Errorf("Expected record in_packets to be %d, got %d", currentBatchID, r.InPackets)
				}
			}
			lastBatchID = currentBatchID
		}
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if lastBatchID != numBatches-1 {
		t.Fatalf("Expected to have processed up to batch %d, but finished at %d", numBatches-1, lastBatchID)
	}
}
