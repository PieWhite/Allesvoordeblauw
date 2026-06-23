// Package scanner contains unit tests for the CSV scanning features, verifying column
// mapping, header shuffling, missing columns, nfdump footers, and error propagation.
package scanner

import (
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"goversion/models"
)

func TestStreamCSV(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantCount     int32
		wantErr       bool
		checkContents func(t *testing.T, recs []models.NetflowRecord)
	}{
		{
			name: "Valid CSV data",
			input: `ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt
2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000
2023-01-01 00:00:02,2023-01-01 00:00:03,192.168.1.2,10.0.0.2,1235,443,UDP,........,5,250`,
			wantCount: 2,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 2 {
					t.Fatalf("Expected 2 records, got %d", len(recs))
				}
				r1 := recs[0]
				if r1.First != "2023-01-01 00:00:00" || r1.Last != "2023-01-01 00:00:01" {
					t.Errorf("First/Last incorrect: first=%q, last=%q", r1.First, r1.Last)
				}
				if r1.Src4Addr != "192.168.1.1" || r1.Dst4Addr != "10.0.0.1" {
					t.Errorf("IPs incorrect: src=%q, dst=%q", r1.Src4Addr, r1.Dst4Addr)
				}
				if r1.SrcPort != 1234 || r1.DstPort != 80 {
					t.Errorf("Ports incorrect: src=%d, dst=%d", r1.SrcPort, r1.DstPort)
				}
				if r1.Proto != 6 || r1.TCPFlags != ".A.S...F" {
					t.Errorf("Proto/Flags incorrect: proto=%d, flags=%q", r1.Proto, r1.TCPFlags)
				}
				if r1.InPackets != 10 || r1.InBytes != 1000 {
					t.Errorf("Packets/Bytes incorrect: pkts=%d, bytes=%d", r1.InPackets, r1.InBytes)
				}
				r2 := recs[1]
				if r2.Proto != 17 || r2.SrcPort != 1235 || r2.DstPort != 443 {
					t.Errorf("Record 2 fields incorrect: proto=%d, src_port=%d, dst_port=%d", r2.Proto, r2.SrcPort, r2.DstPort)
				}
			},
		},
		{
			name: "Varying column order",
			input: `sa,sp,da,dp,pr,ts,te,flg,ibyt,ipkt
192.168.1.1,1234,10.0.0.1,80,TCP,2023-01-01 00:00:00,2023-01-01 00:00:01,.A.S...F,1000,10`,
			wantCount: 1,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 1 {
					t.Fatalf("Expected 1 record, got %d", len(recs))
				}
				r := recs[0]
				if r.Src4Addr != "192.168.1.1" || r.Dst4Addr != "10.0.0.1" || r.SrcPort != 1234 || r.DstPort != 80 {
					t.Errorf("Fields mapped incorrectly with shuffled headers: %+v", r)
				}
				if r.InPackets != 10 || r.InBytes != 1000 || r.Proto != 6 {
					t.Errorf("Metrics/Proto incorrect: %+v", r)
				}
			},
		},
		{
			name: "Missing columns",
			input: `ts,sa,da,sp,dp,pr,ipkt,ibyt
2023-01-01 00:00:00,192.168.1.1,10.0.0.1,1234,80,TCP,10,1000`,
			wantCount: 1,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 1 {
					t.Fatalf("Expected 1 record, got %d", len(recs))
				}
				r := recs[0]
				if r.First != "2023-01-01 00:00:00" || r.Last != "" || r.TCPFlags != "" {
					t.Errorf("Expected empty strings for missing optional columns: %+v", r)
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
			name: "Invalid port data format",
			input: `ts,sa,da,sp,dp,pr,ipkt,ibyt
2023-01-01 00:00:00,192.168.1.1,10.0.0.1,INVALID_PORT,80,TCP,10,1000`,
			wantErr: true,
		},
		{
			name: "With nfdump summary footer",
			input: `ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt
2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000
Summary: 1 flows, 10 packets, 1000 bytes
Time window: 2023-01-01 00:00:00 to 2023-01-01 00:00:01
Total bytes: 1000`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "Large volume",
			input: func() string {
				var sb strings.Builder
				sb.WriteString("ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt\n")
				line := "2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000\n"
				for i := 0; i < 5000; i++ {
					sb.WriteString(line)
				}
				return sb.String()
			}(),
			wantCount: 5000,
			wantErr:   false,
		},
		{
			name: "Headerless CSV input defaults",
			input: `2023-01-01 00:00:00,2023-01-01 00:00:01,0.000,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,0,0,10,1000
2023-01-01 00:00:02,2023-01-01 00:00:03,0.000,192.168.1.2,10.0.0.2,1235,443,UDP,........,0,0,5,250`,
			wantCount: 2,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 2 {
					t.Fatalf("Expected 2 records, got %d", len(recs))
				}
				r1 := recs[0]
				if r1.First != "2023-01-01 00:00:00" || r1.Last != "2023-01-01 00:00:01" {
					t.Errorf("First/Last incorrect: first=%q, last=%q", r1.First, r1.Last)
				}
				if r1.Src4Addr != "192.168.1.1" || r1.Dst4Addr != "10.0.0.1" {
					t.Errorf("IPs incorrect: src=%q, dst=%q", r1.Src4Addr, r1.Dst4Addr)
				}
				if r1.SrcPort != 1234 || r1.DstPort != 80 {
					t.Errorf("Ports incorrect: src=%d, dst=%d", r1.SrcPort, r1.DstPort)
				}
				if r1.Proto != 6 || r1.TCPFlags != ".A.S...F" {
					t.Errorf("Proto/Flags incorrect: proto=%d, flags=%q", r1.Proto, r1.TCPFlags)
				}
				if r1.InPackets != 10 || r1.InBytes != 1000 {
					t.Errorf("Packets/Bytes incorrect: pkts=%d, bytes=%d", r1.InPackets, r1.InBytes)
				}
			},
		},
		{
			name: "Partial error halting",
			input: `ts,sa,da,sp,dp,pr,ipkt,ibyt
2023-01-01 00:00:00,192.168.1.1,10.0.0.1,1234,80,TCP,10,1000
2023-01-01 00:00:02,192.168.1.1,10.0.0.1,INVALID_PORT,80,TCP,10,1000`,
			wantCount: 1,
			wantErr:   true,
			checkContents: func(t *testing.T, recs []models.NetflowRecord) {
				if len(recs) != 1 {
					t.Fatalf("Expected 1 successfully parsed record before the error, got %d", len(recs))
				}
				if recs[0].SrcPort != 1234 {
					t.Errorf("Expected SrcPort 1234, got %d", recs[0].SrcPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var processed int32
			var mu sync.Mutex
			var collected []models.NetflowRecord

			err := StreamCSV(strings.NewReader(tt.input), func(records []models.NetflowRecord) {
				atomic.AddInt32(&processed, int32(len(records)))
				mu.Lock()
				collected = append(collected, records...)
				mu.Unlock()
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("StreamCSV() error = %v, wantErr = %v", err, tt.wantErr)
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

func TestParallelStreamCSV(t *testing.T) {
	tempFile, err := os.CreateTemp("", "test_parallel_csv_*.csv")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	csvContent := `ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt
2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000
2023-01-01 00:00:02,2023-01-01 00:00:03,192.168.1.2,10.0.0.2,1235,443,UDP,........,5,250
`
	if _, err := tempFile.WriteString(csvContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tempFile.Close()

	var records []models.NetflowRecord
	var mu sync.Mutex

	err = ParallelStreamCSV(tempFile.Name(), nil, func(workerID int, recs []models.NetflowRecord) {
		mu.Lock()
		records = append(records, recs...)
		mu.Unlock()
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(records))
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].First < records[j].First
	})

	r1 := records[0]
	if r1.First != "2023-01-01 00:00:00" || r1.Src4Addr != "192.168.1.1" || r1.SrcPort != 1234 {
		t.Errorf("Record 1 incorrect: %+v", r1)
	}

	r2 := records[1]
	if r2.First != "2023-01-01 00:00:02" || r2.Src4Addr != "192.168.1.2" || r2.SrcPort != 1235 {
		t.Errorf("Record 2 incorrect: %+v", r2)
	}
}

func BenchmarkStreamCSV(b *testing.B) {
	const numRecords = 10000
	var sb strings.Builder
	sb.WriteString("ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt\n")
	line := "2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000\n"
	for i := 0; i < numRecords; i++ {
		sb.WriteString(line)
	}
	csvContent := sb.String()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(csvContent)
		_ = StreamCSV(reader, func(records []models.NetflowRecord) {})
	}
}
