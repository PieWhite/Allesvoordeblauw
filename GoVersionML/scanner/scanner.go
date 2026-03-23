package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/goccy/go-json"

	"goversion/models"
)

const chunkSize = 16 * 1024 * 1024 // 16 MB boundary

func StreamNetflow(stream io.Reader, processFn func(models.NetflowRecord)) error {
	reader := bufio.NewReaderSize(stream, 64*1024)
	peek, err := reader.Peek(1)
	if err != nil && err != io.EOF {
		return err
	}
	isArray := len(peek) > 0 && peek[0] == '['

	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}

	chunksChan := make(chan []byte, numWorkers*2)

	type result struct {
		records []models.NetflowRecord
		err     error
	}
	resultsChan := make(chan result, numWorkers*2)

	var wg sync.WaitGroup

	// Workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range chunksChan {
				// Clean up the chunk by removing leading/trailing structural characters.
				cleanChunk := bytes.Trim(bytes.TrimSpace(chunk), "[], \n\r\t")
				if len(cleanChunk) == 0 {
					continue
				}

				// Wrap the clean chunk in brackets to mimic a valid JSON array.
				wrapped := make([]byte, 0, len(cleanChunk)+2)
				wrapped = append(wrapped, '[')
				wrapped = append(wrapped, cleanChunk...)
				wrapped = append(wrapped, ']')

				var records []models.NetflowRecord
				decoder := json.NewDecoder(bytes.NewReader(wrapped))
				
				if err := decoder.Decode(&records); err != nil {
					// Fallback and Error Handling
					if isArray {
						// For strict Array mode, any corruption fails the parse,
						// but we must yield any valid records parsed before the error.
						var validBatch []models.NetflowRecord
						fallbackDecoder := json.NewDecoder(bytes.NewReader(wrapped))
						_, _ = fallbackDecoder.Token() // skip '['
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
						return // Stop this worker
					}

					// For resilient NDJSON, fallback to line-by-line parsing of this chunk
					// to skip broken lines.
					scanner := bufio.NewScanner(bytes.NewReader(chunk))
					var validBatch []models.NetflowRecord
					for scanner.Scan() {
						line := bytes.TrimSpace(scanner.Bytes())
						if len(line) == 0 {
							continue
						}
						// Strip trailing comma for potential Array slices that fell back here
						line = bytes.TrimSuffix(line, []byte(","))

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
					continue
				}

				resultsChan <- result{records: records}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Reader goroutine
	errChan := make(chan error, 1)
	go func() {
		defer close(chunksChan)

		var leftover []byte

		for {
			chunkBuf := make([]byte, chunkSize)
			copied := copy(chunkBuf, leftover)

			n, err := io.ReadFull(reader, chunkBuf[copied:])
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				errChan <- fmt.Errorf("read error: %w", err)
				return
			}

			total := copied + n
			if total == 0 {
				break
			}

			// If we hit EOF, process the rest
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				chunksChan <- chunkBuf[:total]
				break
			}

			// Find boundary
			var idx int
			if isArray {
				// Scan backwards for '}'
				idx = bytes.LastIndexByte(chunkBuf[:total], '}')
			} else {
				// Scan backwards for '\n'
				idx = bytes.LastIndexByte(chunkBuf[:total], '\n')
			}

			if idx == -1 {
				errChan <- fmt.Errorf("record larger than chunk size (16MB)")
				return
			}

			chunksChan <- chunkBuf[:idx+1]

			leftoverLen := total - (idx + 1)
			leftover = make([]byte, leftoverLen)
			copy(leftover, chunkBuf[idx+1:total])
		}
		close(errChan)
	}()

	var firstErr error

	// Main thread dispatch loop
	for res := range resultsChan {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		for _, record := range res.records {
			processFn(record)
		}
	}

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}
