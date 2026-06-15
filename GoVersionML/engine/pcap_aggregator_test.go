package engine

import (
	"math"
	"testing"

	"goversion/models"
)

func TestPcapIPStats_FeatureCalculation(t *testing.T) {
	// Create PCAP stats block for an IP
	ipVal, _ := ParseIPv4("192.168.1.1")
	stats := NewPcapIPStats(ipVal, 1673536500)

	// Simulate 4 TCP packets with varying properties
	packets := []models.PcapRecord{
		{Timestamp: 1673536500.1, SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 80, Length: 60, Proto: 6, TCPFlags: "S"},
		{Timestamp: 1673536500.2, SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 80, Length: 120, Proto: 6, TCPFlags: "A"},
		{Timestamp: 1673536500.4, SrcIP: "192.168.1.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 443, Length: 80, Proto: 6, TCPFlags: "PA"},
		{Timestamp: 1673536500.7, SrcIP: "10.0.0.1", DstIP: "192.168.1.1", SrcPort: 80, DstPort: 12345, Length: 100, Proto: 6, TCPFlags: "R"},
	}

	for _, p := range packets {
		isOutbound := p.SrcIP == "192.168.1.1"
		stats.Update(p, isOutbound)
	}

	// Verify counts
	if stats.PacketCount != 4 {
		t.Fatalf("expected 4 packets, got %d", stats.PacketCount)
	}
	if stats.TotalLength != 360 {
		t.Errorf("expected total length 360, got %f", stats.TotalLength)
	}

	// Calculate vectors (39 features)
	vector := stats.ToPcapMLVector()

	if len(vector) != 39 {
		t.Fatalf("expected 39 features, got %d", len(vector))
	}

	// Verify Header Length: Mean transport header of TCP (4 packets * 20 bytes = 80 / 4 = 20)
	if vector[0] != 20.0 {
		t.Errorf("expected header length 20, got %f", vector[0])
	}

	// Verify Rate: 4 packets over 0.6 seconds -> 4 / 0.6 = 6.6666
	expectedRate := 4.0 / 0.6
	if math.Abs(vector[2]-expectedRate) > 1e-4 {
		t.Errorf("expected rate %f, got %f", expectedRate, vector[2])
	}

	// Verify TCP flags ratios
	if vector[4] != 0.25 { // syn flag number: 1/4 = 0.25
		t.Errorf("expected syn flag number 0.25, got %f", vector[4])
	}
	if vector[7] != 0.50 { // ack flag number: 2/4 = 0.50
		t.Errorf("expected ack flag number 0.50, got %f", vector[7])
	}
	if vector[5] != 0.25 { // rst flag number: 1/4 = 0.25
		t.Errorf("expected rst flag number 0.25, got %f", vector[5])
	}

	// Verify packet counts
	if vector[10] != 1.0 { // syn count
		t.Errorf("expected syn count 1.0, got %f", vector[10])
	}
	if vector[11] != 2.0 { // ack count
		t.Errorf("expected ack count 2.0, got %f", vector[11])
	}

	// Verify protocol/port ratios
	if vector[16] != 0.75 { // HTTP (port 80): 3/4 = 0.75
		t.Errorf("expected HTTP ratio 0.75, got %f", vector[16])
	}
	if vector[15] != 0.25 { // HTTPS (port 443): 1/4 = 0.25
		t.Errorf("expected HTTPS ratio 0.25, got %f", vector[15])
	}

	// Verify Length Stats
	if vector[29] != 360.0 { // Tot Sum
		t.Errorf("expected Tot Sum 360, got %f", vector[29])
	}
	if vector[30] != 60.0 { // Min
		t.Errorf("expected Min 60, got %f", vector[30])
	}
	if vector[31] != 120.0 { // Max
		t.Errorf("expected Max 120, got %f", vector[31])
	}
	if vector[32] != 90.0 { // AVG
		t.Errorf("expected AVG 90, got %f", vector[32])
	}

	// Standard Deviation of [60, 120, 80, 100] -> mean = 90
	// variance = ((60-90)^2 + (120-90)^2 + (80-90)^2 + (100-90)^2) / 3 = (900 + 900 + 100 + 100) / 3 = 2000/3 = 666.6666
	// std = sqrt(666.6666) = 25.8198
	expectedStd := math.Sqrt(2000.0 / 3.0)
	if math.Abs(vector[33]-expectedStd) > 1e-4 {
		t.Errorf("expected Std %f, got %f", expectedStd, vector[33]) // Std is index 33
	}
}

func TestPcapAggregator(t *testing.T) {
	agg := NewPcapAggregator()

	// Feed 3 packets
	agg.Update(models.PcapRecord{Timestamp: 1673536500.1, SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80, Length: 60, Proto: 6})
	agg.Update(models.PcapRecord{Timestamp: 1673536500.2, SrcIP: "192.168.1.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, Length: 80, Proto: 6})
	agg.Update(models.PcapRecord{Timestamp: 1673536900.0, SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80, Length: 100, Proto: 6})

	// Total unique keys in map (Window 1: 1673536500 -> IPs "192.168.1.1", "10.0.0.1", "10.0.0.2")
	// Window 2: 1673536800 -> IPs "192.168.1.1", "10.0.0.1"
	if agg.NumActiveKeys() != 5 {
		t.Errorf("expected 5 map entries, got %d", agg.NumActiveKeys())
	}

	// Flush old windows before 1673536800
	flushed := agg.ExtractAndFlushBefore(1673536800)
	if len(flushed) != 3 {
		t.Errorf("expected 3 flushed stats from first window, got %d", len(flushed))
	}

	for i := 0; i < numPartitions; i++ {
		m := agg.aggregatePartition(i)
		for k := range m {
			t.Logf("Active key: IP=%s, Window=%d", FormatIPv4(k.IP), k.Window)
		}
	}

	// Map should have 2 entries left
	if agg.NumActiveKeys() != 2 {
		t.Errorf("expected 2 remaining entries, got %d", agg.NumActiveKeys())
	}

	// Flush all remaining
	allFlushed := agg.FlushAll()
	if len(allFlushed) != 2 {
		t.Errorf("expected 2 flushed remaining stats, got %d", len(allFlushed))
	}

	if agg.NumActiveKeys() != 0 {
		t.Errorf("expected 0 entries left, got %d", agg.NumActiveKeys())
	}
}
