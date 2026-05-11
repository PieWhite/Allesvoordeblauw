package scannerv2

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
	// Return a valid JSON before failing
	validJSON := []byte(`{"first":"2023-01-01T00:00:00Z","last":"2023-01-01T00:00:01Z","in_packets":10,"in_bytes":100,"proto":6,"tcp_flags":"SYN","src_port":1234,"dst_port":80,"src4_addr":"192.168.1.1","dst4_addr":"10.0.0.1"}` + "\n")
	n = copy(p, validJSON)
	return n, nil
}

func TestStreamNetflowV2_ValidData(t *testing.T) {
	jsonData := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}
`
	reader := strings.NewReader(jsonData)

	var totalProcessed int32
	var mu sync.Mutex
	var processedRecords []models.NetflowRecord

	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
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

func TestStreamNetflowV2_EmptyStream(t *testing.T) {
	reader := strings.NewReader("")

	var totalProcessed int32
	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 0 {
		t.Fatalf("Expected 0 records, got: %d", totalProcessed)
	}
}

func TestStreamNetflowV2_InvalidData(t *testing.T) {
	// Mixed valid and invalid data
	jsonData := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}
INVALID_JSON_HERE
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}`

	reader := strings.NewReader(jsonData)

	var totalProcessed int32
	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	// The scanner should process the 2 valid records and return an error for the invalid one.
	if err == nil {
		t.Fatal("Expected an error due to invalid JSON, got nil")
	}

	if totalProcessed != 2 {
		t.Fatalf("Expected 2 valid records processed, got: %d", totalProcessed)
	}
}

func TestStreamNetflowV2_ScannerError(t *testing.T) {
	expectedErr := errors.New("simulated read error")
	reader := &errorReader{maxReads: 1, err: expectedErr}

	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
		// Do nothing, just consume
	})

	if err == nil {
		t.Fatal("Expected an error from the reader, got nil")
	}

	if !strings.Contains(err.Error(), "simulated read error") {
		t.Fatalf("Expected error to contain 'simulated read error', got: %v", err)
	}
}

func TestStreamNetflowV2_LargeVolume(t *testing.T) {
	const numRecords = 5000 // Creates multiple batches since batchSize is 1000

	var builder strings.Builder
	validJSON := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}` + "\n"
	for i := 0; i < numRecords; i++ {
		builder.WriteString(validJSON)
	}

	reader := strings.NewReader(builder.String())

	var totalProcessed int32
	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != numRecords {
		t.Fatalf("Expected %d records, got: %d", numRecords, totalProcessed)
	}
}

func TestStreamNetflowV2_ArenaGrowth(t *testing.T) {
	// Create a JSON line that is very large to trigger arena growth
	// The default arena is 2MB. We need a line slightly larger than the remaining space or > 2MB.
	// Since 2MB is large, we'll make a 3MB string.
	// We'll pad a string field with a lot of 'A's.
	padding := strings.Repeat("A", 3*1024*1024)
	largeJSON := fmt.Sprintf(`{"first":"%s","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`+"\n", padding)

	reader := strings.NewReader(largeJSON)

	var totalProcessed int32
	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 1 {
		t.Fatalf("Expected 1 record processed, got: %d", totalProcessed)
	}
}

func TestStreamNetflowV2_ProcessFnConcurrency(t *testing.T) {
	// Verify that slices passed to processFn are not corrupted across calls if processFn processes synchronously
	jsonData := `{"in_packets":1}
{"in_packets":2}
{"in_packets":3}
`
	reader := strings.NewReader(jsonData)

	var mu sync.Mutex
	var collected []int64

	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
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

func TestStreamNetflowV2_Resequencing(t *testing.T) {
	// Generate enough records to create multiple batches (batchSize is 1000)
	const numRecords = 5000
	var builder strings.Builder
	for i := 0; i < numRecords; i++ {
		// Store the index in InPackets to verify order
		builder.WriteString(fmt.Sprintf(`{"in_packets":%d}`+"\n", i))
	}

	reader := strings.NewReader(builder.String())
	var lastSeen int64 = -1
	var totalProcessed int32

	err := StreamNetflowV2(reader, func(records []models.NetflowRecord) {
		for _, r := range records {
			if r.InPackets != lastSeen+1 {
				t.Errorf("Out of order record! Expected %d, got %d", lastSeen+1, r.InPackets)
			}
			lastSeen = r.InPackets
			atomic.AddInt32(&totalProcessed, 1)
		}
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != numRecords {
		t.Fatalf("Expected %d records, got %d", numRecords, totalProcessed)
	}
}
