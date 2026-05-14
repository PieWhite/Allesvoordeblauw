package JSONScanner

import (
	"sync"
	"testing"

	"goversion/models"
)

func TestProcessJsonArray(t *testing.T) {
	t.Run("Valid Array Chunk", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan models.ScanResult, 1)

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
		if res.Err != nil {
			t.Fatalf("unexpected Err: %v", res.Err)
		}
		if len(*res.Records) != 2 {
			t.Fatalf("expected 2 Records, got %v", len(*res.Records))
		}
	})

	t.Run("Corrupted Array Chunk - Fallback Recovery", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan models.ScanResult, 2)

		var wg sync.WaitGroup
		wg.Add(1)

		// Create a chunk with valid initial Records but a trailing corruption
		chunk := make([]byte, chunkSize)
		data := []byte(`{"src4_addr": "1.1.1.1"},{"src4_addr": "2.2.2.2"},{corrupted}`)
		copy(chunk, data)
		chunksChan <- chunk[:len(data)]
		close(chunksChan)

		go processJsonArray(chunksChan, resultsChan, &wg)
		wg.Wait()
		close(resultsChan)

		// Read all models.ScanResults to see where it Errored
		successRecords := 0
		var finalErr error
		for r := range resultsChan {
			if r.Err != nil {
				finalErr = r.Err
			} else {
				successRecords += len(*r.Records)
			}
		}

		if finalErr == nil {
			t.Fatalf("expected Error from corrupted token")
		}
		if successRecords != 2 {
			t.Fatalf("expected 2 recovered Records, got %d", successRecords)
		}
	})
}

func TestProcessJsonLines(t *testing.T) {
	t.Run("Valid NDJSON Chunk", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan models.ScanResult, 1)

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
		if res.Err != nil {
			t.Fatalf("unexpected Err: %v", res.Err)
		}
		if len(*res.Records) != 2 {
			t.Fatalf("expected 2 Records, got %v", len(*res.Records))
		}
	})

	t.Run("Corrupted NDJSON Chunk - Continues", func(t *testing.T) {
		chunksChan := make(chan []byte, 1)
		resultsChan := make(chan models.ScanResult, 1)

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
		if res.Err != nil {
			t.Fatalf("unexpected Err: %v", res.Err)
		}
		// Expect exactly 2 Records. The broken line should be detected and skipped without failure.
		if len(*res.Records) != 2 {
			t.Fatalf("expected 2 successful Records, got %d", len(*res.Records))
		}
	})
}
