package scanner

import (
	"sync"
	"testing"
)

func TestProcessJsonArray(t *testing.T) {
	t.Run("Valid Array Chunk", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan result, 1)

		var wg sync.WaitGroup
		wg.Add(1)

		// Create a valid chunk
		chunk := make([]byte, chunkSize)
		data := []byte(`{"src4_addr": "1.1.1.1"},{"src4_addr": "2.2.2.2"}`)
		copy(chunk, data)
		chunksChan <- chunk[:len(data)]
		close(chunksChan)

		go processJsonArray(chunksChan, resultsChan, &wg)
		wg.Wait()
		close(resultsChan)

		res := <-resultsChan
		if res.err != nil {
			t.Fatalf("unexpected err: %v", res.err)
		}
		if len(*res.records) != 2 {
			t.Fatalf("expected 2 records, got %v", len(*res.records))
		}
	})

	t.Run("Corrupted Array Chunk - Fallback Recovery", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan result, 2)

		var wg sync.WaitGroup
		wg.Add(1)

		// Create a chunk with valid initial records but a trailing corruption
		chunk := make([]byte, chunkSize)
		data := []byte(`{"src4_addr": "1.1.1.1"},{"src4_addr": "2.2.2.2"},{corrupted}`)
		copy(chunk, data)
		chunksChan <- chunk[:len(data)]
		close(chunksChan)

		go processJsonArray(chunksChan, resultsChan, &wg)
		wg.Wait()
		close(resultsChan)

		// Read all results to see where it errored
		successRecords := 0
		var finalErr error
		for r := range resultsChan {
			if r.err != nil {
				finalErr = r.err
			} else {
				successRecords += len(*r.records)
			}
		}

		if finalErr == nil {
			t.Fatalf("expected error from corrupted token")
		}
		if successRecords != 2 {
			t.Fatalf("expected 2 recovered records, got %d", successRecords)
		}
	})
}

func TestProcessJsonLines(t *testing.T) {
	t.Run("Valid NDJSON Chunk", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan result, 1)

		var wg sync.WaitGroup
		wg.Add(1)

		chunk := make([]byte, chunkSize)
		data := []byte(`{"src4_addr": "1.1.1.1"}` + "\n" + `{"src4_addr": "2.2.2.2"}`)
		copy(chunk, data)
		chunksChan <- chunk[:len(data)]
		close(chunksChan)

		go processJsonLines(chunksChan, resultsChan, &wg)
		wg.Wait()
		close(resultsChan)

		res := <-resultsChan
		if res.err != nil {
			t.Fatalf("unexpected err: %v", res.err)
		}
		if len(*res.records) != 2 {
			t.Fatalf("expected 2 records, got %v", len(*res.records))
		}
	})

	t.Run("Corrupted NDJSON Chunk - Continues", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan result, 1)

		var wg sync.WaitGroup
		wg.Add(1)

		chunk := make([]byte, chunkSize)
		// Provide 3 lines: 1 valid, 1 strictly invalid JSON syntax, 1 semantically invalid but syntactically valid (json.Valid passes but Unmarshal fails, e.g. wrong types, though models might tolerate missing. Let's provide a real strictly invalid first)
		data := []byte(`{"src4_addr": "1.1.1.1"}
{this is completely broken}
{"src4_addr": "2.2.2.2"}`)
		copy(chunk, data)
		chunksChan <- chunk[:len(data)]
		close(chunksChan)

		go processJsonLines(chunksChan, resultsChan, &wg)
		wg.Wait()
		close(resultsChan)

		res := <-resultsChan
		if res.err != nil {
			t.Fatalf("unexpected err: %v", res.err)
		}
		// Expect exactly 2 records. The broken line should be detected and skipped without failure.
		if len(*res.records) != 2 {
			t.Fatalf("expected 2 successful records, got %d", len(*res.records))
		}
	})
}
