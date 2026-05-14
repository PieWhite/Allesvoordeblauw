package JSONScanner

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
		recordsPtr := recordsPool.Get().(*[]models.NetflowRecord)
		*recordsPtr = (*recordsPtr)[:0]

		wrappedBuf, err := decodeChunkArray(chunk, recordsPtr)

		returnChunkToPool(chunk)

		if err != nil && wrappedBuf != nil {
			fallbackDecoder := json.NewDecoder(bytes.NewReader(wrappedBuf.Bytes()))
			_, _ = fallbackDecoder.Token()
			for fallbackDecoder.More() {
				var rec models.NetflowRecord
				if errUnm := fallbackDecoder.Decode(&rec); errUnm != nil {
					resultsChan <- result{records: recordsPtr}
					resultsChan <- result{err: fmt.Errorf("json array corruption: %w", errUnm)}
					wrapPool.Put(wrappedBuf)
					return
				}
				*recordsPtr = append(*recordsPtr, rec)
			}
			resultsChan <- result{records: recordsPtr}
			wrapPool.Put(wrappedBuf)
			continue
		}

		if wrappedBuf != nil {
			wrapPool.Put(wrappedBuf)
		}

		if len(*recordsPtr) > 0 {
			resultsChan <- result{records: recordsPtr}
		} else {
			recordsPool.Put(recordsPtr)
		}
	}
}

func processJsonLines(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		recordsPtr := recordsPool.Get().(*[]models.NetflowRecord)
		records := *recordsPtr
		records = records[:0]

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
			records = append(records, rec)
		}

		if len(records) > 0 {
			*recordsPtr = records
			resultsChan <- result{records: recordsPtr}
		} else {
			recordsPool.Put(recordsPtr)
		}

		returnChunkToPool(chunk)
	}
}
