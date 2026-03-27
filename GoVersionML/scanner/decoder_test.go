package scanner

import (
	"testing"
)

func TestDecodeChunkArray(t *testing.T) {
	t.Run("Valid JSON", func(t *testing.T) {
		input := []byte(`{"src4_addr": "1.1.1.1"}, {"src4_addr": "2.2.2.2"}`)
		records, wrapped, err := decodeChunkArray(input)

		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(records))
		}
		if records[0].Src4Addr != "1.1.1.1" {
			t.Errorf("unexpected record 0: %v", records[0])
		}
		if wrapped == nil {
			t.Errorf("expected wrapped to not be nil")
		} else {
			wrapPool.Put(wrapped)
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		input := []byte(`{"src4_addr": "1.1.1.1" --- }`)
		records, wrapped, err := decodeChunkArray(input)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if records != nil {
			t.Errorf("expected records to be nil")
		}
		if string(wrapped.Bytes()) != `[{"src4_addr": "1.1.1.1" --- }]` {
			t.Errorf("wrapped string unexpectedly modified: %s", string(wrapped.Bytes()))
		}
		wrapPool.Put(wrapped)
	})

	t.Run("Empty Input", func(t *testing.T) {
		input := []byte(" \n\r ")
		records, wrapped, err := decodeChunkArray(input)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if records != nil || wrapped != nil {
			t.Errorf("expected nil for records and wrapped on empty input")
		}
	})
}
