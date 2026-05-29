package scanner

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"goversion/models"
)

// makeMockPcap creates a valid in-memory PCAP stream for testing
func makeMockPcap(t *testing.T, isBigEndian bool, numPackets int) []byte {
	var buf bytes.Buffer

	// 1. PCAP Global Header (24 bytes)
	globalHdr := make([]byte, 24)
	var byteOrder binary.ByteOrder = binary.LittleEndian
	if isBigEndian {
		byteOrder = binary.BigEndian
	}
	byteOrder.PutUint32(globalHdr[0:4], 0xa1b2c3d4) // Magic (correctly encodes swapped bytes when BigEndian)
	byteOrder.PutUint16(globalHdr[4:6], 2)   // Major Version
	byteOrder.PutUint16(globalHdr[6:8], 4)   // Minor Version
	byteOrder.PutUint32(globalHdr[8:12], 0)  // Gmt to local correction
	byteOrder.PutUint32(globalHdr[12:16], 0) // Accuracy of timestamps
	byteOrder.PutUint32(globalHdr[16:20], 65535) // Max octets allowed per packet
	byteOrder.PutUint32(globalHdr[20:24], 1) // LinkType (1 = Ethernet)

	buf.Write(globalHdr)

	// 2. Build packet payload (54 bytes: 14B Eth + 20B IPv4 + 20B TCP)
	payload := []byte{
		// Ethernet Header (14 bytes)
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Source MAC
		0x08, 0x00,                         // EtherType (IPv4)

		// IPv4 Header (20 bytes)
		0x45,                               // Version (4) & IHL (5 -> 20 bytes)
		0x00,                               // Differentiated Services
		0x00, 0x28,                         // Total Length (40 bytes = 20B IP + 20B TCP)
		0x12, 0x34,                         // Identification
		0x40, 0x00,                         // Flags (Don't Fragment) & Fragment Offset
		0x40,                               // TTL (64)
		0x06,                               // Protocol (6 = TCP)
		0x00, 0x00,                         // Header Checksum
		192, 168, 1, 1,                     // Source IP (192.168.1.1)
		10, 0, 0, 1,                        // Destination IP (10.0.0.1)

		// TCP Header (20 bytes)
		0x30, 0x39,                         // Source Port (12345)
		0x00, 0x50,                         // Destination Port (80)
		0x00, 0x00, 0x00, 0x01,             // Sequence Number
		0x00, 0x00, 0x00, 0x02,             // Acknowledgment Number
		0x50,                               // Data Offset (5 -> 20 bytes) & Reserved
		0x02,                               // TCP Flags (0x02 = SYN)
		0x10, 0x00,                         // Window Size
		0x00, 0x00,                         // Checksum
		0x00, 0x00,                         // Urgent Pointer
	}

	// 3. Write multiple packet entries
	for i := 0; i < numPackets; i++ {
		pktHdr := make([]byte, 16)
		byteOrder.PutUint32(pktHdr[0:4], 1673536740 + uint32(i)) // Seconds
		byteOrder.PutUint32(pktHdr[4:8], 100000 + uint32(i))    // Microseconds
		byteOrder.PutUint32(pktHdr[8:12], uint32(len(payload))) // Captured packet size
		byteOrder.PutUint32(pktHdr[12:16], uint32(len(payload))) // Original packet size

		buf.Write(pktHdr)
		buf.Write(payload)
	}

	return buf.Bytes()
}

func TestStreamPCAP_LittleEndian(t *testing.T) {
	data := makeMockPcap(t, false, 5)
	reader := bytes.NewReader(data)

	var records []models.PcapRecord
	err := StreamPCAP(reader, func(batch []models.PcapRecord) {
		records = append(records, batch...)
	})

	if err != nil {
		t.Fatalf("StreamPCAP failed: %v", err)
	}

	if len(records) != 5 {
		t.Fatalf("Expected 5 records, got %d", len(records))
	}

	r := records[0]
	if r.Timestamp != 1673536740.100000 {
		t.Errorf("Expected timestamp 1673536740.1, got %f", r.Timestamp)
	}
	if r.SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP '192.168.1.1', got '%s'", r.SrcIP)
	}
	if r.DstIP != "10.0.0.1" {
		t.Errorf("Expected DstIP '10.0.0.1', got '%s'", r.DstIP)
	}
	if r.SrcPort != 12345 {
		t.Errorf("Expected SrcPort 12345, got %d", r.SrcPort)
	}
	if r.DstPort != 80 {
		t.Errorf("Expected DstPort 80, got %d", r.DstPort)
	}
	if r.Length != 54 {
		t.Errorf("Expected Length 54, got %d", r.Length)
	}
	if r.Proto != 6 {
		t.Errorf("Expected Proto 6, got %d", r.Proto)
	}
	if r.TCPFlags != "S" {
		t.Errorf("Expected TCPFlags 'S', got '%s'", r.TCPFlags)
	}
}

func TestStreamPCAP_BigEndian(t *testing.T) {
	data := makeMockPcap(t, true, 3)
	reader := bytes.NewReader(data)

	var records []models.PcapRecord
	err := StreamPCAP(reader, func(batch []models.PcapRecord) {
		records = append(records, batch...)
	})

	if err != nil {
		t.Fatalf("StreamPCAP failed: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("Expected 3 records, got %d", len(records))
	}

	r := records[2]
	if r.Timestamp != 1673536742.100002 {
		t.Errorf("Expected timestamp 1673536742.100002, got %f", r.Timestamp)
	}
}

func TestStreamPCAP_InvalidMagic(t *testing.T) {
	invalidData := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	reader := bytes.NewReader(invalidData)

	err := StreamPCAP(reader, func(batch []models.PcapRecord) {})
	if err == nil {
		t.Fatal("Expected error for invalid PCAP magic, got nil")
	}

	if !strings.Contains(err.Error(), "invalid pcap magic") {
		t.Errorf("Expected error to contain 'invalid pcap magic', got: %v", err)
	}
}

func TestStreamPCAP_UnsupportedLinkType(t *testing.T) {
	var buf bytes.Buffer
	globalHdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(globalHdr[0:4], 0xa1b2c3d4) // Magic
	binary.LittleEndian.PutUint32(globalHdr[20:24], 105)       // LinkType (105 is not Ethernet)
	buf.Write(globalHdr)

	reader := bytes.NewReader(buf.Bytes())
	err := StreamPCAP(reader, func(batch []models.PcapRecord) {})
	if err == nil {
		t.Fatal("Expected error for unsupported link type, got nil")
	}

	if !strings.Contains(err.Error(), "unsupported pcap link type") {
		t.Errorf("Expected error to contain 'unsupported pcap link type', got: %v", err)
	}
}

func BenchmarkStreamPCAP(b *testing.B) {
	data := makeMockPcap(nil, false, 1000)
	reader := bytes.NewReader(data)
	fn := func(batch []models.PcapRecord) {
		// consume
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_ = StreamPCAP(reader, fn)
	}
}
