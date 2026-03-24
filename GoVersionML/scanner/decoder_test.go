package scanner

import (
	"testing"
)

func TestWrapChunk(t *testing.T) {
	t.Run("Clean Chunk", func(t *testing.T) {
		input := []byte(`{"src4_addr": "1.1.1.1"}`)
		expected := `[{"src4_addr": "1.1.1.1"}]`
		
		result := wrapChunk(input)
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("Empty Chunk", func(t *testing.T) {
		input := []byte(" \n\r\t ")
		result := wrapChunk(input)
		if result != nil {
			t.Errorf("expected nil result for empty chunk, got %v", result)
		}
	})

	t.Run("Trailing Commas and Brackets", func(t *testing.T) {
		input := []byte(` {"src4_addr": "1.1.1.1"}, `)
		expected := `[{"src4_addr": "1.1.1.1"}]`
		
		result := wrapChunk(input)
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})
}

func TestDecodeChunk(t *testing.T) {
	t.Run("Valid JSON", func(t *testing.T) {
		input := []byte(`{"src4_addr": "1.1.1.1"}, {"src4_addr": "2.2.2.2"}`)
		records, wrapped, err := decodeChunk(input)
		
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(records))
		}
		if records[0].Src4Addr != "1.1.1.1" {
			t.Errorf("unexpected record 0: %v", records[0])
		}
		if wrapped != nil {
			t.Errorf("expected wrapped to be nil on success, got %s", string(wrapped))
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		input := []byte(`{"src4_addr": "1.1.1.1" --- }`)
		records, wrapped, err := decodeChunk(input)
		
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if records != nil {
			t.Errorf("expected records to be nil")
		}
		if string(wrapped) != `[{"src4_addr": "1.1.1.1" --- }]` {
			t.Errorf("wrapped string unexpectedly modified: %s", string(wrapped))
		}
	})

	t.Run("Empty Input", func(t *testing.T) {
		input := []byte(" \n\r ")
		records, wrapped, err := decodeChunk(input)
		
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if records != nil || wrapped != nil {
			t.Errorf("expected nil for records and wrapped on empty input")
		}
	})
}
