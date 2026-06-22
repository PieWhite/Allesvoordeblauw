// Package scanner contains unit tests for the PCAP scanner, verifying parsing of little-endian
// and big-endian PCAP captures, handling of invalid headers, and link type validation.
package scanner

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"goversion/models"
)

func makeMockPcap(isBigEndian bool, numPackets int) []byte {
	var buf bytes.Buffer

	globalHdr := make([]byte, 24)
	var byteOrder binary.ByteOrder = binary.LittleEndian
	if isBigEndian {
		byteOrder = binary.BigEndian
	}
	byteOrder.PutUint32(globalHdr[0:4], 0xa1b2c3d4)
	byteOrder.PutUint16(globalHdr[4:6], 2)
	byteOrder.PutUint16(globalHdr[6:8], 4)
	byteOrder.PutUint32(globalHdr[8:12], 0)
	byteOrder.PutUint32(globalHdr[12:16], 0)
	byteOrder.PutUint32(globalHdr[16:20], 65535)
	byteOrder.PutUint32(globalHdr[20:24], 1)

	buf.Write(globalHdr)

	payload := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x08, 0x00,
		0x45,
		0x00,
		0x00, 0x28,
		0x12, 0x34,
		0x40, 0x00,
		0x40,
		0x06,
		0x00, 0x00,
		192, 168, 1, 1,
		10, 0, 0, 1,
		0x30, 0x39,
		0x00, 0x50,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
		0x50,
		0x02,
		0x10, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}

	for i := 0; i < numPackets; i++ {
		pktHdr := make([]byte, 16)
		byteOrder.PutUint32(pktHdr[0:4], 1673536740+uint32(i))
		byteOrder.PutUint32(pktHdr[4:8], 100000+uint32(i))
		byteOrder.PutUint32(pktHdr[8:12], uint32(len(payload)))
		byteOrder.PutUint32(pktHdr[12:16], uint32(len(payload)))

		buf.Write(pktHdr)
		buf.Write(payload)
	}

	return buf.Bytes()
}

func TestStreamPCAP(t *testing.T) {
	tests := []struct {
		name          string
		input         func() []byte
		wantCount     int
		wantErr       bool
		checkContents func(t *testing.T, recs []models.PcapRecord)
	}{
		{
			name: "Little Endian valid PCAP",
			input: func() []byte {
				return makeMockPcap(false, 5)
			},
			wantCount: 5,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.PcapRecord) {
				if len(recs) != 5 {
					t.Fatalf("Expected 5 records, got %d", len(recs))
				}
				r := recs[0]
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
			},
		},
		{
			name: "Big Endian valid PCAP",
			input: func() []byte {
				return makeMockPcap(true, 3)
			},
			wantCount: 3,
			wantErr:   false,
			checkContents: func(t *testing.T, recs []models.PcapRecord) {
				if len(recs) != 3 {
					t.Fatalf("Expected 3 records, got %d", len(recs))
				}
				r := recs[2]
				if r.Timestamp != 1673536742.100002 {
					t.Errorf("Expected timestamp 1673536742.100002, got %f", r.Timestamp)
				}
			},
		},
		{
			name: "Invalid magic number",
			input: func() []byte {
				return make([]byte, 24)
			},
			wantErr: true,
		},
		{
			name: "Unsupported Link Type",
			input: func() []byte {
				var buf bytes.Buffer
				globalHdr := make([]byte, 24)
				binary.LittleEndian.PutUint32(globalHdr[0:4], 0xa1b2c3d4)
				binary.LittleEndian.PutUint32(globalHdr[20:24], 105)
				buf.Write(globalHdr)
				return buf.Bytes()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var collected []models.PcapRecord
			err := StreamPCAP(bytes.NewReader(tt.input()), func(batch []models.PcapRecord) {
				collected = append(collected, batch...)
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("StreamPCAP() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if err != nil && !strings.Contains(err.Error(), "magic") && !strings.Contains(err.Error(), "link type") {
					t.Errorf("Expected parse magic/link error, got: %v", err)
				}
				return
			}

			if len(collected) != tt.wantCount {
				t.Errorf("Expected %d records parsed, got %d", tt.wantCount, len(collected))
			}

			if tt.checkContents != nil {
				tt.checkContents(t, collected)
			}
		})
	}
}

func BenchmarkStreamPCAP(b *testing.B) {
	data := makeMockPcap(false, 1000)
	reader := bytes.NewReader(data)
	fn := func(batch []models.PcapRecord) {}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(data)
		_ = StreamPCAP(reader, fn)
	}
}
