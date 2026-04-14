package netflowscanner

import (
	"bytes"
	"strings"
	"testing"

	"goversion/models"
)

// Standard TCP record from demo-raw.netflow format
const sampleTCPRecord = `
Flow Record: 
  RecordCount  =             52274338
  Flags        =              0x02 SFLOW v5, Sampled
  Elements     =                 3: 1 2 15 
  size         =               112
  engine type  =                 0
  engine ID    =                 0
  export sysid =                 4
  first        =     1739429195920 [2025-02-13 07:46:35.920]
  last         =     1739429195920 [2025-02-13 07:46:35.920]
  received at  =     1739429195920 [2025-02-13 07:46:35.920]
  proto        =                 6 TCP
  tcp flags    =              0x18 ...AP...
  src port     =             52357
  dst port     =              3389
  src tos      =                 2
  fwd status   =                 0
  in packets   =             10000
  in bytes     =           1050000
  src addr     =    194.180.49.205
  dst addr     =     217.23.12.128
  in src mac   = 74:83:ef:46:b2:fa
  out dst mac  = 44:4c:a8:a3:01:e3
  in dst mac   = 00:00:00:00:00:00
  out src mac  = 00:00:00:00:00:00
`

func TestStreamNetflowText_SingleTCPRecord(t *testing.T) {
	reader := strings.NewReader(sampleTCPRecord)
	var totalRecords int

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		for _, rec := range records {
			totalRecords++

			if rec.Src4Addr != "194.180.49.205" {
				t.Errorf("expected src addr 194.180.49.205, got %q", rec.Src4Addr)
			}
			if rec.Dst4Addr != "217.23.12.128" {
				t.Errorf("expected dst addr 217.23.12.128, got %q", rec.Dst4Addr)
			}
			if rec.SrcPort != 52357 {
				t.Errorf("expected src port 52357, got %d", rec.SrcPort)
			}
			if rec.DstPort != 3389 {
				t.Errorf("expected dst port 3389, got %d", rec.DstPort)
			}
			if rec.Proto != 6 {
				t.Errorf("expected proto 6, got %d", rec.Proto)
			}
			if rec.InPackets != 10000 {
				t.Errorf("expected in_packets 10000, got %d", rec.InPackets)
			}
			if rec.InBytes != 1050000 {
				t.Errorf("expected in_bytes 1050000, got %d", rec.InBytes)
			}
			if rec.ExportSysID != 4 {
				t.Errorf("expected export_sysid 4, got %d", rec.ExportSysID)
			}

			// TCP flags 0x18 = ACK + PSH → "...AP..."
			if !strings.Contains(rec.TCPFlags, "A") {
				t.Errorf("expected A flag in tcp_flags %q", rec.TCPFlags)
			}
			if !strings.Contains(rec.TCPFlags, "P") {
				t.Errorf("expected P flag in tcp_flags %q", rec.TCPFlags)
			}

			// Timestamp: 1739429195920 ms → UTC = 2025-02-13T06:46:35.920
			if rec.First != "2025-02-13T06:46:35.920" {
				t.Errorf("expected first 2025-02-13T06:46:35.920, got %q", rec.First)
			}
		}
	})

	if err != nil {
		t.Fatalf("StreamNetflowText returned error: %v", err)
	}
	if totalRecords != 1 {
		t.Errorf("expected 1 record, got %d", totalRecords)
	}
}

// ICMP record: no src/dst port, has "ICMP = 0.0 type.code" instead
const sampleICMPRecord = `
Flow Record: 
  RecordCount  =             140339851
  Flags        =              0x02 SFLOW v5, Sampled
  Elements     =                 3: 1 2 15 
  size         =               112
  engine type  =                 0
  engine ID    =                 0
  export sysid =                 4
  first        =     1739464518213 [2025-02-13 17:35:18.213]
  last         =     1739464518213 [2025-02-13 17:35:18.213]
  received at  =     1739464518212 [2025-02-13 17:35:18.212]
  proto        =                 1 ICMP
  tcp flags    =              0x00 ........
  ICMP         =               0.0  type.code
  in packets   =             10000
  in bytes     =           1060000
  src addr     =           8.8.8.8
  dst addr     =     217.23.12.128
  in src mac   = 74:83:ef:46:b3:01
  out dst mac  = 44:4c:a8:a3:01:e3
  in dst mac   = 00:00:00:00:00:00
  out src mac  = 00:00:00:00:00:00
`

func TestStreamNetflowText_ICMPRecord(t *testing.T) {
	reader := strings.NewReader(sampleICMPRecord)
	var totalRecords int

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		for _, rec := range records {
			totalRecords++
			if rec.Proto != 1 {
				t.Errorf("expected proto 1, got %d", rec.Proto)
			}
			if rec.SrcPort != 0 {
				t.Errorf("expected src port 0 for ICMP, got %d", rec.SrcPort)
			}
			if rec.DstPort != 0 {
				t.Errorf("expected dst port 0 for ICMP, got %d", rec.DstPort)
			}
			if rec.Src4Addr != "8.8.8.8" {
				t.Errorf("expected src addr 8.8.8.8, got %q", rec.Src4Addr)
			}
			if rec.InBytes != 1060000 {
				t.Errorf("expected in_bytes 1060000, got %d", rec.InBytes)
			}
		}
	})

	if err != nil {
		t.Fatalf("StreamNetflowText returned error: %v", err)
	}
	if totalRecords != 1 {
		t.Errorf("expected 1 record, got %d", totalRecords)
	}
}

// Record with ip next hop (optional field)
const sampleNextHopRecord = `
Flow Record: 
  RecordCount  =             813818710
  Flags        =              0x02 SFLOW v5, Sampled
  Elements     =                 4: 1 2 10 15 
  size         =               120
  engine type  =                 0
  engine ID    =                 0
  export sysid =                 6
  first        =     1739570859569 [2025-02-14 23:07:39.569]
  last         =     1739570859569 [2025-02-14 23:07:39.569]
  received at  =     1739570859569 [2025-02-14 23:07:39.569]
  proto        =                 6 TCP
  tcp flags    =              0x10 ...A....
  src port     =              3389
  dst port     =             54937
  src tos      =                 0
  fwd status   =                 0
  in packets   =             10000
  in bytes     =            680000
  src addr     =     217.23.12.128
  dst addr     =      45.94.218.49
  ip next hop  =    109.236.95.226
  in src mac   = a8:a1:59:37:5a:5b
  out dst mac  = 00:1c:73:00:00:97
  in dst mac   = 00:00:00:00:00:00
  out src mac  = 00:00:00:00:00:00
`

func TestStreamNetflowText_NextHopRecord(t *testing.T) {
	reader := strings.NewReader(sampleNextHopRecord)
	var totalRecords int

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		for _, rec := range records {
			totalRecords++
			if rec.IPNextHop != "109.236.95.226" {
				t.Errorf("expected ip next hop 109.236.95.226, got %q", rec.IPNextHop)
			}
			if rec.ExportSysID != 6 {
				t.Errorf("expected export_sysid 6, got %d", rec.ExportSysID)
			}
		}
	})

	if err != nil {
		t.Fatalf("StreamNetflowText returned error: %v", err)
	}
	if totalRecords != 1 {
		t.Errorf("expected 1 record, got %d", totalRecords)
	}
}

func TestStreamNetflowText_MultipleRecords(t *testing.T) {
	input := sampleTCPRecord + sampleICMPRecord + sampleNextHopRecord
	reader := strings.NewReader(input)
	var totalRecords int

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		totalRecords += len(records)
	})

	if err != nil {
		t.Fatalf("StreamNetflowText returned error: %v", err)
	}
	if totalRecords != 3 {
		t.Errorf("expected 3 records, got %d", totalRecords)
	}
}

func TestStreamNetflowText_EmptyInput(t *testing.T) {
	reader := strings.NewReader("")
	called := false

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		called = true
	})

	if err != nil {
		t.Fatalf("Expected no error for empty input, got: %v", err)
	}
	if called {
		t.Error("processFn should not be called for empty input")
	}
}

func TestStreamNetflowText_SummaryIgnored(t *testing.T) {
	input := sampleTCPRecord + `Summary: total flows: 1, total bytes: 1 M
Time window: 2025-02-13 00:00:00 - 2025-02-14 23:59:59
Total flows processed: 1, passed: 1, Blocks skipped: 0
`
	reader := strings.NewReader(input)
	var totalRecords int

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		totalRecords += len(records)
	})

	if err != nil {
		t.Fatalf("StreamNetflowText returned error: %v", err)
	}
	if totalRecords != 1 {
		t.Errorf("expected 1 record (summary lines ignored), got %d", totalRecords)
	}
}

func TestStreamNetflowText_TCPFlagsConversion(t *testing.T) {
	tests := []struct {
		name     string
		hexInput string
		wantS    bool // SYN
		wantA    bool // ACK
		wantR    bool // RST
		wantF    bool // FIN
	}{
		{"SYN only", "0x02", true, false, false, false},
		{"ACK only", "0x10", false, true, false, false},
		{"SYN+ACK", "0x12", true, true, false, false},
		{"RST", "0x04", false, false, true, false},
		{"ACK+PSH", "0x18", false, true, false, false},
		{"FIN+ACK", "0x11", false, true, false, true},
		{"None", "0x00", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTCPFlagsVisual(tt.hexInput)
			if strings.Contains(result, "S") != tt.wantS {
				t.Errorf("SYN: got %q, wantS=%v", result, tt.wantS)
			}
			if strings.Contains(result, "A") != tt.wantA {
				t.Errorf("ACK: got %q, wantA=%v", result, tt.wantA)
			}
			if strings.Contains(result, "R") != tt.wantR {
				t.Errorf("RST: got %q, wantR=%v", result, tt.wantR)
			}
			if strings.Contains(result, "F") != tt.wantF {
				t.Errorf("FIN: got %q, wantF=%v", result, tt.wantF)
			}
		})
	}
}

func TestStreamNetflowText_Batching(t *testing.T) {
	// Generate enough records to trigger multiple batches
	var sb strings.Builder
	for i := 0; i < netflowBatchSize+100; i++ {
		sb.WriteString(sampleTCPRecord)
	}

	reader := strings.NewReader(sb.String())
	batchCount := 0
	totalRecords := 0

	err := StreamNetflowText(reader, func(records []models.NetflowRecord) {
		batchCount++
		totalRecords += len(records)
	})

	if err != nil {
		t.Fatalf("StreamNetflowText returned error: %v", err)
	}
	if totalRecords != netflowBatchSize+100 {
		t.Errorf("expected %d records, got %d", netflowBatchSize+100, totalRecords)
	}
	if batchCount < 2 {
		t.Errorf("expected at least 2 batches for %d records, got %d", netflowBatchSize+100, batchCount)
	}
}

// Benchmark to verify zero-ish allocation performance
func BenchmarkStreamNetflowText(b *testing.B) {
	// Build a chunk of 1000 records
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString(sampleTCPRecord)
	}
	data := []byte(sb.String())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		_ = StreamNetflowText(reader, func(records []models.NetflowRecord) {})
	}
}
