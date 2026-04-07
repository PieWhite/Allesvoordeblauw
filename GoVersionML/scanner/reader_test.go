package scanner

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestChunkPool(t *testing.T) {
	t.Run("Get New Chunk", func(t *testing.T) {
		ptr := chunkPool.Get().(*[]byte)
		chunk := *ptr
		if len(chunk) != chunkSize {
			t.Errorf("expected len %d, got %d", chunkSize, len(chunk))
		}
		if cap(chunk) != chunkSize {
			t.Errorf("expected cap %d, got %d", chunkSize, cap(chunk))
		}
	})

	t.Run("Return and Re-Get Chunk", func(t *testing.T) {
		ptr1 := chunkPool.Get().(*[]byte)
		(*ptr1)[0] = 0xAA

		returnChunkToPool(*ptr1)

		ptr2 := chunkPool.Get().(*[]byte)
		chunk2 := *ptr2
		if len(chunk2) != chunkSize {
			t.Errorf("expected len %d", chunkSize)
		}
		
		// Testing if we actually pull from the pool is somewhat tricky due to gc runtime
		// but we can verify it doesn't panic.
	})

	t.Run("Return Incorrect Capacity", func(t *testing.T) {
		badChunk := make([]byte, 100)
		returnChunkToPool(badChunk)
		// No panic means success. The pool handles it safely via size check.
	})
}

func TestReadjsonByDelimiter(t *testing.T) {
	t.Run("Normal NDJSON Newline Delimiting", func(t *testing.T) {
		input := "line1\nline2\nline3\n"
		r := strings.NewReader(input)
		
		chunksChan := make(chan []byte, 10)
		errChan := make(chan error, 1)

		readjsonByDelimiter(r, chunksChan, errChan, '\n')

		err := <-errChan
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var results [][]byte
		for c := range chunksChan {
			results = append(results, c)
		}

		if len(results) != 1 {
			t.Errorf("expected 1 chunk batch initially, got %d", len(results))
		} else {
			if string(results[0]) != "line1\nline2\nline3\n" {
				t.Errorf("unexpected content: %s", string(results[0]))
			}
		}
	})

	t.Run("Normal JSON Array Bracket Delimiting", func(t *testing.T) {
		input := `{"a": 1},{"b": 2}`
		r := strings.NewReader(input)
		
		chunksChan := make(chan []byte, 10)
		errChan := make(chan error, 1)

		readjsonByDelimiter(r, chunksChan, errChan, '}')

		err := <-errChan
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var results [][]byte
		for c := range chunksChan {
			results = append(results, c)
		}

		if len(results) != 1 {
			t.Errorf("expected 1 chunk batch initially, got %d", len(results))
		} else {
			if string(results[0]) != `{"a": 1},{"b": 2}` {
				t.Errorf("unexpected content: %s", string(results[0]))
			}
		}
	})

	t.Run("Record Larger Than Chunk", func(t *testing.T) {
		// Mock reader that just spits out 'a' without newlines to exhaust chunk.
		r := bytes.NewReader(bytes.Repeat([]byte("a"), chunkSize+10))

		chunksChan := make(chan []byte, 10)
		errChan := make(chan error, 1)

		readjsonByDelimiter(r, chunksChan, errChan, '\n')
		err := <-errChan
		if err == nil {
			t.Fatal("expected record larger than chunk size error, got nil")
		}
		if !strings.Contains(err.Error(), "record larger than chunk size") {
			t.Errorf("unexpected error text: %v", err)
		}
	})

	t.Run("Read Error", func(t *testing.T) {
		expectedErr := errors.New("read failed")
		r := &errReader{err: expectedErr}

		chunksChan := make(chan []byte, 10)
		errChan := make(chan error, 1)

		readjsonByDelimiter(r, chunksChan, errChan, '\n')
		err := <-errChan
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "read failed") {
			t.Errorf("unexpected error text: %v", err)
		}
	})

	t.Run("Empty Reader", func(t *testing.T) {
		r := strings.NewReader("")
		
		chunksChan := make(chan []byte, 10)
		errChan := make(chan error, 1)

		readjsonByDelimiter(r, chunksChan, errChan, '\n')
		err := <-errChan
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// chunksChan should be closed with nothing in it
		if _, open := <-chunksChan; open {
			t.Error("expected chunksChan to be closed")
		}
	})
}
