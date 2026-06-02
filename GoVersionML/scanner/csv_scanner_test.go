package scanner

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"goversion/models"
)

func TestStreamCSV_ValidData(t *testing.T) {
	csvData := `ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt
2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000
2023-01-01 00:00:02,2023-01-01 00:00:03,192.168.1.2,10.0.0.2,1235,443,UDP,........,5,250
`
	reader := strings.NewReader(csvData)

	var totalProcessed int32
	var mu sync.Mutex
	var processedRecords []models.NetflowRecord

	err := StreamCSV(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
		mu.Lock()
		processedRecords = append(processedRecords, records...)
		mu.Unlock()
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 2 {
		t.Fatalf("Expected 2 records, got %d", totalProcessed)
	}

	// Verify fields
	r1 := processedRecords[0]
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

	r2 := processedRecords[1]
	if r2.Proto != 17 || r2.SrcPort != 1235 || r2.DstPort != 443 {
		t.Errorf("Record 2 fields incorrect: proto=%d, src_port=%d, dst_port=%d", r2.Proto, r2.SrcPort, r2.DstPort)
	}
}

func TestStreamCSV_VaryingColumnOrder(t *testing.T) {
	csvData := `sa,sp,da,dp,pr,ts,te,flg,ibyt,ipkt
192.168.1.1,1234,10.0.0.1,80,TCP,2023-01-01 00:00:00,2023-01-01 00:00:01,.A.S...F,1000,10
`
	reader := strings.NewReader(csvData)

	var processed []models.NetflowRecord
	err := StreamCSV(reader, func(records []models.NetflowRecord) {
		processed = append(processed, records...)
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(processed) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(processed))
	}

	r := processed[0]
	if r.Src4Addr != "192.168.1.1" || r.Dst4Addr != "10.0.0.1" || r.SrcPort != 1234 || r.DstPort != 80 {
		t.Errorf("Fields mapped incorrectly with shuffled headers: %+v", r)
	}
	if r.InPackets != 10 || r.InBytes != 1000 || r.Proto != 6 {
		t.Errorf("Metrics/Proto incorrect: %+v", r)
	}
}

func TestStreamCSV_MissingColumns(t *testing.T) {
	// A CSV that lacks flags and end-timestamp entirely
	csvData := `ts,sa,da,sp,dp,pr,ipkt,ibyt
2023-01-01 00:00:00,192.168.1.1,10.0.0.1,1234,80,TCP,10,1000
`
	reader := strings.NewReader(csvData)

	var processed []models.NetflowRecord
	err := StreamCSV(reader, func(records []models.NetflowRecord) {
		processed = append(processed, records...)
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(processed) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(processed))
	}

	r := processed[0]
	if r.First != "2023-01-01 00:00:00" || r.Last != "" || r.TCPFlags != "" {
		t.Errorf("Expected empty strings for missing optional columns: %+v", r)
	}
}

func TestStreamCSV_EmptyStream(t *testing.T) {
	err := StreamCSV(strings.NewReader(""), func(records []models.NetflowRecord) {})
	if err != nil {
		t.Fatalf("Expected no error for empty stream, got: %v", err)
	}
}

func TestStreamCSV_InvalidData(t *testing.T) {
	csvData := `ts,sa,da,sp,dp,pr,ipkt,ibyt
2023-01-01 00:00:00,192.168.1.1,10.0.0.1,INVALID_PORT,80,TCP,10,1000
`
	reader := strings.NewReader(csvData)

	err := StreamCSV(reader, func(records []models.NetflowRecord) {})
	if err == nil {
		t.Fatal("Expected error from invalid port digits, got nil")
	}
}

func TestStreamCSV_WithNfdumpSummaryFooter(t *testing.T) {
	csvData := `ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt
2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000
Summary: 1 flows, 10 packets, 1000 bytes
Time window: 2023-01-01 00:00:00 to 2023-01-01 00:00:01
Total bytes: 1000
`
	reader := strings.NewReader(csvData)

	var totalProcessed int32
	err := StreamCSV(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != 1 {
		t.Fatalf("Expected only 1 record (ignoring footers), got: %d", totalProcessed)
	}
}

func TestStreamCSV_LargeVolume(t *testing.T) {
	const numRecords = 5000
	var sb strings.Builder
	sb.WriteString("ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt\n")
	line := "2023-01-01 00:00:00,2023-01-01 00:00:01,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,10,1000\n"
	for i := 0; i < numRecords; i++ {
		sb.WriteString(line)
	}

	reader := strings.NewReader(sb.String())
	var totalProcessed int32
	err := StreamCSV(reader, func(records []models.NetflowRecord) {
		atomic.AddInt32(&totalProcessed, int32(len(records)))
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if totalProcessed != numRecords {
		t.Fatalf("Expected %d records, got %d", numRecords, totalProcessed)
	}
}

func TestStreamCSV_Headerless(t *testing.T) {
	// A headerless CSV with nfdump columns:
	// ts, te, td, sa, da, sp, dp, pr, flg, fwd, stos, ipkt, ibyt
	csvData := `2023-01-01 00:00:00,2023-01-01 00:00:01,0.000,192.168.1.1,10.0.0.1,1234,80,TCP,.A.S...F,0,0,10,1000
2023-01-01 00:00:02,2023-01-01 00:00:03,0.000,192.168.1.2,10.0.0.2,1235,443,UDP,........,0,0,5,250
`
	reader := strings.NewReader(csvData)

	var processed []models.NetflowRecord
	err := StreamCSV(reader, func(records []models.NetflowRecord) {
		processed = append(processed, records...)
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(processed) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(processed))
	}

	r1 := processed[0]
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

	r2 := processed[1]
	if r2.First != "2023-01-01 00:00:02" || r2.SrcPort != 1235 || r2.DstPort != 443 || r2.Proto != 17 || r2.InPackets != 5 || r2.InBytes != 250 {
		t.Errorf("Record 2 fields incorrect: %+v", r2)
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
		_ = StreamCSV(reader, func(records []models.NetflowRecord) {
			// consume
		})
	}
}
