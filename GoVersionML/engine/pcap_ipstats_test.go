package engine

import (
	"testing"

	"goversion/models"
)

func TestPcapIPStats_UpdateAndFeatures(t *testing.T) {
	ipVal, _ := ParseIPv4("192.168.1.50")
	stats := NewPcapIPStats(ipVal, 1680000000)

	// Add 3 mock packets
	// Packet 1: TCP Syn, Length 100, DstPort 80 (HTTP outbound)
	stats.Update(models.PcapRecord{
		Timestamp: 1680000000.0,
		Length:    100,
		Proto:     6, // TCP
		TCPFlags:  "S",
		SrcPort:   12345,
		DstPort:   80,
	}, true)

	// Packet 2: TCP Syn-Ack, Length 200, SrcPort 80 (HTTP inbound)
	stats.Update(models.PcapRecord{
		Timestamp: 1680000001.0, // IAT = 1.0s
		Length:    200,
		Proto:     6, // TCP
		TCPFlags:  "SA",
		SrcPort:   80,
		DstPort:   12345,
	}, false)

	// Packet 3: UDP, Length 300, DstPort 53 (DNS outbound)
	stats.Update(models.PcapRecord{
		Timestamp: 1680000003.0, // IAT = 2.0s
		Length:    300,
		Proto:     17, // UDP
		TCPFlags:  "",
		SrcPort:   54321,
		DstPort:   53,
	}, true)

	// Basic Counts Check
	if stats.PacketCount != 3 {
		t.Errorf("Expected 3 packets, got %d", stats.PacketCount)
	}
	if stats.TotalLength != 600 {
		t.Errorf("Expected total length 600, got %f", stats.TotalLength)
	}
	if stats.MinLength != 100 {
		t.Errorf("Expected min length 100, got %f", stats.MinLength)
	}
	if stats.MaxLength != 300 {
		t.Errorf("Expected max length 300, got %f", stats.MaxLength)
	}

	// Flag Counts
	if stats.SynCount != 2 {
		t.Errorf("Expected 2 SYN packets, got %d", stats.SynCount)
	}
	if stats.AckCount != 1 {
		t.Errorf("Expected 1 ACK packet, got %d", stats.AckCount)
	}

	// Protocols
	if stats.TCPCount != 2 {
		t.Errorf("Expected 2 TCP packets, got %d", stats.TCPCount)
	}
	if stats.UDPCount != 1 {
		t.Errorf("Expected 1 UDP packet, got %d", stats.UDPCount)
	}

	// Applications
	if stats.HTTPCount != 2 {
		t.Errorf("Expected 2 HTTP packets (port 80), got %d", stats.HTTPCount)
	}
	if stats.DNSCount != 1 {
		t.Errorf("Expected 1 DNS packet (port 53), got %d", stats.DNSCount)
	}

	// Call feature generation
	features := stats.ToPcapMLVector()

	// Verify length (MUST be 39 features)
	if len(features) != 39 {
		t.Fatalf("Expected 39 ML features, got %d", len(features))
	}

	// Rates: total 3 packets over 3.0s window span (1680000003 - 1680000000)
	// Rate average is at index 2 (features[2])
	rate := features[2]
	if rate <= 0 {
		t.Errorf("Rate calculation should be positive, got %f", rate)
	}
}
