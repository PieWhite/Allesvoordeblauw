package ingest

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goversion/models"
)

func TestDetectInputFormatByPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    InputFormat
		wantErr bool
	}{
		{name: "json lower", path: "sample.json", want: InputFormatJSON},
		{name: "json upper", path: "sample.JSON", want: InputFormatJSON},
		{name: "netflow", path: "sample.netflow", want: InputFormatNetflow},
		{name: "binetflow", path: "sample.binetflow", want: InputFormatNetflow},
		{name: "unsupported", path: "sample.exe", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectInputFormatByPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.path)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("format mismatch: got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- MOCK SECTION ---
// MockScanner implements the Scanner interface for unit testing Ingestor logic.

type MockScanner struct {
	Called bool
	Err    error
}

func (m *MockScanner) StreamNetflow(r io.Reader, fn func(models.NetflowRecord)) error {
	m.Called = true
	if fn != nil {
		fn(models.NetflowRecord{Src4Addr: "1.1.1.1", Dst4Addr: "2.2.2.2"})
	}
	return m.Err
}

type MockParser struct {
	Records []models.NetflowRecord
	Err     error
}

func (m *MockParser) Parse(r io.Reader) ([]models.NetflowRecord, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Records, nil
}

// --- UNIT TESTS ---
// These tests verify that Ingestor handles files and routing correctly.

func TestIngestor_ProcessInput(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Valid JSON Calls Scanner", func(t *testing.T) {
		mock := &MockScanner{}
		i := &Ingestor{NetflowScanner: mock}
		path := filepath.Join(tmpDir, "test.json")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, func(r models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Expected success, got err: %v", err)
		}
		if !mock.Called {
			t.Error("Ingestor did not delegate work to the Scanner interface")
		}
	})

	t.Run("Case Insensitivity Check", func(t *testing.T) {
		mock := &MockScanner{}
		i := &Ingestor{NetflowScanner: mock}
		path := filepath.Join(tmpDir, "UPPER.JSON")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, func(r models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Ingestor failed uppercase extension check: %v", err)
		}
	})

	t.Run("Unsupported Extension Returns Error", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: &MockScanner{}}
		path := filepath.Join(tmpDir, "test.exe")
		os.WriteFile(path, []byte("binary data"), 0644)

		err := i.ProcessInput(path, nil)
		if err == nil {
			t.Error("Expected error for .exe, got nil")
		}
	})

	t.Run("Netflow Extension Uses NetflowParser", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: &MockScanner{}}
		path := filepath.Join(tmpDir, "flows.netflow")
		os.WriteFile(path, []byte("2|1739429195920|1739429195920|6|0|0|0|3266589133|52357|0|0|0|3642166400|3389|0|0|0|0|24|2|10000|1050000\n"), 0644)

		got := 0
		err := i.ProcessInput(path, func(r models.NetflowRecord) {
			got++
		})
		if err != nil {
			t.Fatalf("Expected successful .netflow parse, got error: %v", err)
		}
		if got != 1 {
			t.Fatalf("Expected one parsed record, got %d", got)
		}
	})

	t.Run("File Not Found Error", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: &MockScanner{}}
		err := i.ProcessInput("missing_file.json", nil)
		if err == nil || !strings.Contains(err.Error(), "failed to open input file") {
			t.Errorf("Expected file open error, got: %v", err)
		}
	})

	t.Run("Scanner Not Initialized", func(t *testing.T) {
		i := &Ingestor{NetflowScanner: nil}
		path := filepath.Join(tmpDir, "nil_test.json")
		os.WriteFile(path, []byte("{}"), 0644)

		err := i.ProcessInput(path, nil)
		if err == nil || err.Error() != "scanner not initialized" {
			t.Errorf("Expected nil-scanner error, got: %v", err)
		}
	})

	t.Run("Uses ParserFactory Seam", func(t *testing.T) {
		records := []models.NetflowRecord{{Src4Addr: "10.0.0.1"}, {Src4Addr: "10.0.0.2"}}
		i := &Ingestor{
			ParserFactory: func(path string, scanner Scanner) (Parser, error) {
				return &MockParser{Records: records}, nil
			},
		}

		path := filepath.Join(tmpDir, "factory.json")
		os.WriteFile(path, []byte("{}"), 0644)

		got := 0
		err := i.ProcessInput(path, func(r models.NetflowRecord) {
			got++
		})
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if got != len(records) {
			t.Fatalf("expected %d processed records, got %d", len(records), got)
		}
	})
}

func TestNewParserByPath(t *testing.T) {
	t.Run("Returns JSONParser", func(t *testing.T) {
		p, err := NewParserByPath("input.json", &MockScanner{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := p.(*JSONParser); !ok {
			t.Fatalf("expected *JSONParser, got %T", p)
		}
	})

	t.Run("Returns NetflowParser", func(t *testing.T) {
		p, err := NewParserByPath("input.netflow", &MockScanner{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := p.(*NetflowParser); !ok {
			t.Fatalf("expected *NetflowParser, got %T", p)
		}
	})
}

func TestNetflowParser_Parse(t *testing.T) {
	p := &NetflowParser{}

	t.Run("Pipe Format", func(t *testing.T) {
		line := "2|1739429195920|1739429195920|6|0|0|0|3266589133|52357|0|0|0|3642166400|3389|0|0|0|0|24|2|10000|1050000"
		records, err := p.Parse(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].Src4Addr != "194.180.49.205" || records[0].Dst4Addr != "217.23.12.128" {
			t.Fatalf("unexpected IP mapping: %+v", records[0])
		}
	})

	t.Run("CSV Format", func(t *testing.T) {
		line := "2025-02-13 07:46:35,2025-02-13 07:46:35,0.000,194.180.49.205,217.23.12.128,52357,3389,TCP,...AP...,0,2,10000,1050000"
		records, err := p.Parse(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].Proto != 6 || records[0].InPackets != 10000 || records[0].InBytes != 1050000 {
			t.Fatalf("unexpected csv mapping: %+v", records[0])
		}
	})

	t.Run("Whitespace Text Format", func(t *testing.T) {
		line := "2025-02-13 07:46:35.920 00:00:00.000 TCP 194.180.49.205:52357 -> 217.23.12.128:3389 10000 1.1 M 1"
		records, err := p.Parse(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].InBytes != 1100000 {
			t.Fatalf("expected scaled bytes 1100000, got %d", records[0].InBytes)
		}
	})

	t.Run("Malformed Lines Are Skipped", func(t *testing.T) {
		input := strings.Join([]string{
			"bad line with no useful fields",
			"2|1739429195920|1739429195920|6|0|0|0|3266589133|52357|0|0|0|3642166400|3389|0|0|0|0|24|2|10000|1050000",
			"still bad",
		}, "\n")
		records, err := p.Parse(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 valid parsed record, got %d", len(records))
		}
	})

	t.Run("Raw Block Flow Record Format", func(t *testing.T) {
		input := strings.Join([]string{
			"Flow Record:",
			"  first        =     1739429195920 [2025-02-13 07:46:35.920]",
			"  last         =     1739429195920 [2025-02-13 07:46:35.920]",
			"  received at  =     1739429195920 [2025-02-13 07:46:35.920]",
			"  proto        =                 6 TCP",
			"  tcp flags    =              0x18 ...AP...",
			"  src port     =             52357",
			"  dst port     =              3389",
			"  in packets   =             10000",
			"  in bytes     =           1050000",
			"  src addr     =    194.180.49.205",
			"  dst addr     =     217.23.12.128",
			"",
		}, "\n")

		records, err := p.Parse(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record from raw block format, got %d", len(records))
		}
		if records[0].Src4Addr != "194.180.49.205" || records[0].Dst4Addr != "217.23.12.128" {
			t.Fatalf("unexpected parsed IPs: %+v", records[0])
		}
	})
}

type errReader struct{}

func (e errReader) Read(p []byte) (int, error) {
	return 0, errors.New("forced read error")
}

func TestNetflowParser_Parse_ReadError(t *testing.T) {
	p := &NetflowParser{}
	_, err := p.Parse(errReader{})
	if err == nil || !strings.Contains(err.Error(), "read netflow input") {
		t.Fatalf("expected wrapped read error, got: %v", err)
	}
}

func TestNormalizeNetflowRecord(t *testing.T) {
	input := models.NetflowRecord{
		Type:      "",
		Proto:     0,
		TCPFlags:  "...AP...",
		SrcPort:   -10,
		DstPort:   99999,
		InPackets: -5,
		InBytes:   -100,
		Src4Addr:  "194.180.49.205",
		Dst4Addr:  "bad-ip",
		First:     "2025-02-13 07:46:35.920",
		Last:      "",
		Received:  "",
	}

	n := NormalizeNetflowRecord(input)

	if n.Type != "FLOW" {
		t.Fatalf("expected default type FLOW, got %q", n.Type)
	}
	if n.Proto != 6 {
		t.Fatalf("expected proto normalized to TCP(6), got %d", n.Proto)
	}
	if n.SrcPort != 0 || n.DstPort != 65535 {
		t.Fatalf("expected clamped ports, got src=%d dst=%d", n.SrcPort, n.DstPort)
	}
	if n.InPackets != 0 || n.InBytes != 0 {
		t.Fatalf("expected non-negative counters, got packets=%d bytes=%d", n.InPackets, n.InBytes)
	}
	if n.Src4Addr != "194.180.49.205" || n.Dst4Addr != "" {
		t.Fatalf("expected src kept and invalid dst cleared, got src=%q dst=%q", n.Src4Addr, n.Dst4Addr)
	}
	if n.First == "" || n.Last == "" || n.Received == "" {
		t.Fatalf("expected normalized timestamps to be populated, got first=%q last=%q received=%q", n.First, n.Last, n.Received)
	}
}

func TestIngestor_ProcessInput_NormalizesRecords(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "norm.netflow")
	os.WriteFile(path, []byte("2|1739429195920|1739429195920|6|0|0|0|3266589133|52357|0|0|0|3642166400|3389|0|0|0|0|24|2|10000|1050000\n"), 0644)

	i := &Ingestor{NetflowScanner: &MockScanner{}}
	var got models.NetflowRecord

	err := i.ProcessInput(path, func(r models.NetflowRecord) {
		got = r
	})
	if err != nil {
		t.Fatalf("unexpected process error: %v", err)
	}
	if got.First == "" || got.Last == "" || got.Received == "" {
		t.Fatalf("expected normalized timestamps in callback record, got %+v", got)
	}
}

func TestNewParserByPathWithOverride(t *testing.T) {
	t.Run("override netflow for json extension", func(t *testing.T) {
		p, err := NewParserByPathWithOverride("input.json", &MockScanner{}, InputFormatNetflow)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := p.(*NetflowParser); !ok {
			t.Fatalf("expected *NetflowParser, got %T", p)
		}
	})

	t.Run("override json for netflow extension", func(t *testing.T) {
		p, err := NewParserByPathWithOverride("input.netflow", &MockScanner{}, InputFormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := p.(*JSONParser); !ok {
			t.Fatalf("expected *JSONParser, got %T", p)
		}
	})
}

func TestJSONScanner_Bridge(t *testing.T) {
	s := &JSONScanner{}

	t.Run("Verify Execution Path", func(t *testing.T) {
		r := strings.NewReader(`[]`)

		err := s.StreamNetflow(r, func(record models.NetflowRecord) {
		})

		if err != nil {
			t.Errorf("Bridge failed: scanner returned unexpected error: %v", err)
		}
	})
}
