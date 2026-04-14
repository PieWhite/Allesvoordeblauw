package scanner

import (
	"errors"
	"strings"
	"testing"

	"goversion/models"
)

// A mocked reader to simulate read errors.
type errReader struct{ err error }

func (e *errReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func TestStreamNetflow(t *testing.T) {
	t.Run("Valid JSON Array", func(t *testing.T) {
		input := `[{"src4_addr": "1.2.3.4"}, {"src4_addr": "5.6.7.8"}]`
		r := strings.NewReader(input)

		var count int
		err := StreamNetflow(r, func(records []models.NetflowRecord) {
			count += len(records)
		})

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 records, got %d", count)
		}
	})

	t.Run("Empty Array", func(t *testing.T) {
		input := `[]`
		r := strings.NewReader(input)

		var count int
		err := StreamNetflow(r, func(records []models.NetflowRecord) {
			count += len(records)
		})

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if count != 0 {
			t.Errorf("Expected 0 records, got %d", count)
		}
	})

	t.Run("Empty Input", func(t *testing.T) {
		r := strings.NewReader("")
		err := StreamNetflow(r, func(records []models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Expected nil for empty input, got %v", err)
		}
	})

	t.Run("Read Error Initial", func(t *testing.T) {
		expectedErr := errors.New("mock read error initial")
		r := &errReader{err: expectedErr}

		err := StreamNetflow(r, func(records []models.NetflowRecord) {})
		if err == nil || !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Errorf("expected wrapped %v, got %v", expectedErr, err)
		}
	})

	t.Run("Full Record Fields", func(t *testing.T) {
		input := `[{
			"type": "NETFLOW",
			"proto": 6,
			"tcp_flags": "S",
			"src_port": 12345,
			"dst_port": 80,
			"in_packets": 10,
			"in_bytes": 500,
			"src4_addr": "192.168.1.1",
			"dst4_addr": "10.0.0.1",
			"first": "2023-01-01T00:00:00.000",
			"last": "2023-01-01T00:00:01.000",
			"received": "2023-01-01T00:00:02.000",
			"in_src_mac": "aa:bb:cc:dd:ee:ff",
			"out_dst_mac": "11:22:33:44:55:66",
			"export_sysid": 1
		}]`
		r := strings.NewReader(input)

		var received []models.NetflowRecord
		err := StreamNetflow(r, func(records []models.NetflowRecord) {
			received = append(received, records...)
		})

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(received) != 1 {
			t.Fatalf("Expected 1 record, got %d", len(received))
		}

		rec := received[0]
		if rec.Proto != 6 {
			t.Errorf("Proto: expected 6, got %d", rec.Proto)
		}
		if rec.Src4Addr != "192.168.1.1" {
			t.Errorf("Src4Addr: expected 192.168.1.1, got %s", rec.Src4Addr)
		}
		if rec.InBytes != 500 {
			t.Errorf("InBytes: expected 500, got %d", rec.InBytes)
		}
	})
}
