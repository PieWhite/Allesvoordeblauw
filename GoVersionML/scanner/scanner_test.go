// Package scanner contains unit tests for the scanner package, validating concurrent
// stream-parsing of JSON and NDJSON formatted logs under various data constraints.
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
	validJSON := []byte(`[{"first":"2023-01-01T00:00:00Z","last":"2023-01-01T00:00:01Z","in_packets":10,"in_bytes":100,"proto":6,"tcp_flags":"SYN","src_port":1234,"dst_port":80,"src4_addr":"192.168.1.1","dst4_addr":"10.0.0.1"},`)
	n = copy(p, validJSON)
	return n, nil
}

func TestStreamJSON(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantCount     int32
		wantErr       bool
		checkContents func(t *testing.T, recs []models.NetflowRecord)
	}{
		{
			name: "Valid JSON array",
			input: `[
{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"},
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}
]`,
			wantCount: 2,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 2 {
					t.Fatalf("Expected 2 records, got %d", len(recs))
				}
				if recs[0].Src4Addr != "1.1.1.1" || recs[1].Src4Addr != "1.1.1.2" {
					t.Errorf("Unexpected record contents: %+v", recs)
				}
			},
		},
		{
			name:      "Empty stream",
			input:     "",
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "Invalid JSON array",
			input: `[
{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"},
{INVALID_JSON_HERE},
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}
]`,
			wantErr: true,
		},
		{
			name: "Large volume",
			input: func() string {
				var sb strings.Builder
				sb.WriteString("[\n")
				record := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`
				for i := 0; i < 5000; i++ {
					sb.WriteString(record)
					if i < 4999 {
						sb.WriteString(",\n")
					}
				}
				sb.WriteString("\n]")
				return sb.String()
			}(),
			wantCount: 5000,
			wantErr:   false,
		},
		{
			name: "Arena growth",
			input: func() string {
				padding := strings.Repeat("A", 3*1024*1024)
				return fmt.Sprintf(`[{"first":"%s","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}]`, padding)
			}(),
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "Incomplete array at EOF",
			input:     `{"first":"1","last":"2"`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "Empty array with noise spaces and commas",
			input:     `[ , ,   , ]`,
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var processed int32
			var mu sync.Mutex
			var collected []models.NetflowRecord

			err := StreamJSON(strings.NewReader(tt.input), func(records []models.NetflowRecord) {
				atomic.AddInt32(&processed, int32(len(records)))
				mu.Lock()
				collected = append(collected, records...)
				mu.Unlock()
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("StreamJSON() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if processed != tt.wantCount {
				t.Errorf("Expected %d processed records, got %d", tt.wantCount, processed)
			}

			if tt.checkContents != nil {
				tt.checkContents(t, collected)
			}
		})
	}
}

func TestStreamNDJSON(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantCount     int32
		wantErr       bool
		checkContents func(t *testing.T, recs []models.NetflowRecord)
	}{
		{
			name: "Valid NDJSON",
			input: `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}`,
			wantCount: 2,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 2 {
					t.Fatalf("Expected 2 records, got %d", len(recs))
				}
				if recs[0].Src4Addr != "1.1.1.1" || recs[1].Src4Addr != "1.1.1.2" {
					t.Errorf("Unexpected record contents: %+v", recs)
				}
			},
		},
		{
			name: "Invalid NDJSON line included",
			input: `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}
{INVALID_NDJSON_HERE}
{"first":"3","last":"4","in_packets":2,"in_bytes":20,"proto":17,"tcp_flags":"","src_port":124,"dst_port":457,"src4_addr":"1.1.1.2","dst4_addr":"2.2.2.3"}`,
			wantCount: 2,
			wantErr:   true,
		},
		{
			name:      "Empty lines and noise",
			input:     "\n\n   \n,\n\n  ,\n",
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var processed int32
			var mu sync.Mutex
			var collected []models.NetflowRecord

			err := StreamNDJSON(strings.NewReader(tt.input), func(records []models.NetflowRecord) {
				atomic.AddInt32(&processed, int32(len(records)))
				mu.Lock()
				collected = append(collected, records...)
				mu.Unlock()
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("StreamNDJSON() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if processed != tt.wantCount {
				t.Errorf("Expected %d processed records, got %d", tt.wantCount, processed)
			}

			if tt.checkContents != nil {
				tt.checkContents(t, collected)
			}
		})
	}
}

func TestStreamNetflow_ScannerError(t *testing.T) {
	expectedErr := errors.New("simulated read error")
	reader := &errorReader{maxReads: 1, err: expectedErr}

	err := StreamJSON(reader, func(records []models.NetflowRecord) {})

	if err == nil {
		t.Fatal("Expected an error from the reader, got nil")
	}

	if !strings.Contains(err.Error(), "simulated read error") {
		t.Fatalf("Expected error to contain 'simulated read error', got: %v", err)
	}
}

func TestStreamNetflow_ProcessFnConcurrency(t *testing.T) {
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

	found := make(map[int64]bool)
	for _, v := range collected {
		found[v] = true
	}
	if !found[1] || !found[2] || !found[3] {
		t.Fatalf("Expected 1, 2, and 3, got: %v", collected)
	}
}

func TestStreamNetflow_WorkerErrorHaltsProducer(t *testing.T) {
	const numRecords = 2005
	var builder strings.Builder
	builder.WriteString("[\n")
	validJSON := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`

	for i := 0; i < 1000; i++ {
		builder.WriteString(validJSON)
		builder.WriteString(",\n")
	}
	builder.WriteString(`{INVALID_JSON_HERE}`)
	builder.WriteString(",\n")

	for i := 0; i < 1004; i++ {
		builder.WriteString(validJSON)
		if i < 1003 {
			builder.WriteString(",\n")
		}
	}
	builder.WriteString("\n]")

	reader := strings.NewReader(builder.String())

	err := StreamJSON(reader, func(records []models.NetflowRecord) {})

	if err == nil {
		t.Fatal("Expected an error due to invalid JSON halting scanner, got nil")
	}
}

func TestStreamNetflow_SequentialOrder(t *testing.T) {
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
			if currentBatchID != lastBatchID+1 {
				t.Errorf("Expected batch ID %d, but got %d (out of order!)", lastBatchID+1, currentBatchID)
			}
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

func TestStreamNetflow_MissingSequenceNoise(t *testing.T) {
	const batchSize = 1000
	var builder strings.Builder

	validRecord := `{"first":"1","last":"2","in_packets":1,"in_bytes":10,"proto":6,"tcp_flags":"S","src_port":123,"dst_port":456,"src4_addr":"1.1.1.1","dst4_addr":"2.2.2.2"}`

	for i := 0; i < batchSize; i++ {
		builder.WriteString(validRecord)
		builder.WriteByte('\n')
	}
	for i := 0; i < batchSize; i++ {
		builder.WriteString(",   \n")
	}
	for i := 0; i < batchSize; i++ {
		builder.WriteString(validRecord)
		builder.WriteByte('\n')
	}

	reader := strings.NewReader(builder.String())

	var totalProcessed int32
	err := StreamNDJSON(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if totalProcessed != 2*batchSize {
		t.Fatalf("Expected %d records processed, but got %d (data was dropped!)", 2*batchSize, totalProcessed)
	}
}
