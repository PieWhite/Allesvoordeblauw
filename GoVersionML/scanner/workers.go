package scanner

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/goccy/go-json"

	"goversion/models"
)

func processJsonArray(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		records, wrappedBuf, err := decodeChunkArray(chunk)

		returnChunkToPool(chunk)

		if err != nil && wrappedBuf != nil {
			validBatch := make([]models.NetflowRecord, 0, 1000)
			fallbackDecoder := json.NewDecoder(bytes.NewReader(wrappedBuf.Bytes()))
			_, _ = fallbackDecoder.Token()
			for fallbackDecoder.More() {
				var rec models.NetflowRecord
				if errUnm := fallbackDecoder.Decode(&rec); errUnm != nil {
					resultsChan <- result{records: validBatch}
					resultsChan <- result{err: fmt.Errorf("json array corruption: %w", errUnm)}
					wrapPool.Put(wrappedBuf)
					return
				}
				validBatch = append(validBatch, rec)
			}
			resultsChan <- result{records: validBatch}
			wrapPool.Put(wrappedBuf)
			continue
		}

		if wrappedBuf != nil {
			wrapPool.Put(wrappedBuf)
		}

		if records != nil {
			resultsChan <- result{records: records}
		}
	}
}

func processJsonLines(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		validBatch := make([]models.NetflowRecord, 0, 1000)

		start := 0
		for start < len(chunk) {
			end := bytes.IndexByte(chunk[start:], '\n')
			if end == -1 {
				end = len(chunk) - start
			}

			line := chunk[start : start+end]
			start += end + 1

			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			line = bytes.TrimSuffix(line, []byte{','})

			if !json.Valid(line) {
				fmt.Printf("Skipping malformed JSON line: strictly invalid syntax\n")
				continue
			}

			var rec models.NetflowRecord
			if errUnm := json.Unmarshal(line, &rec); errUnm != nil {
				fmt.Printf("Skipping malformed NDJSON line: %v\n", errUnm)
				continue
			}
			validBatch = append(validBatch, rec)
		}

		resultsChan <- result{records: validBatch}
		returnChunkToPool(chunk)
	}
}
