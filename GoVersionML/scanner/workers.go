package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"sync"

	"github.com/goccy/go-json"

	"goversion/models"
)

func processJsonArray(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		records, wrapped, err := decodeChunk(chunk)

		returnChunkToPool(chunk)

		if err != nil && len(wrapped) > 0 {
			validBatch := make([]models.NetflowRecord, 0, 1000)
			fallbackDecoder := json.NewDecoder(bytes.NewReader(wrapped))
			_, _ = fallbackDecoder.Token()
			for fallbackDecoder.More() {
				var rec models.NetflowRecord
				if errUnm := fallbackDecoder.Decode(&rec); errUnm != nil {
					resultsChan <- result{records: validBatch}
					resultsChan <- result{err: fmt.Errorf("json array corruption: %w", errUnm)}
					return
				}
				validBatch = append(validBatch, rec)
			}
			resultsChan <- result{records: validBatch}
			return
		}

		if records != nil {
			resultsChan <- result{records: records}
		}
	}
}

func processJsonLines(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		records, _, err := decodeChunk(chunk)
		if err != nil {

			scanner := bufio.NewScanner(bytes.NewReader(chunk))
			validBatch := make([]models.NetflowRecord, 0, 1000)
			for scanner.Scan() {
				line := bytes.TrimSpace(scanner.Bytes())
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
			continue
		}

		returnChunkToPool(chunk)

		if records != nil {
			resultsChan <- result{records: records}
		}
	}
}
