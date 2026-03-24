package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/goccy/go-json"

	"goversion/models"
	"goversion/utils"
)

const chunkSize = 16 * 1024 * 1024 // 16 MB boundary

type result struct {
	records []models.NetflowRecord
	err     error
}

func isArray(stream io.Reader) (bool, io.Reader, error) {
	// Read exactly 1 byte to determine if it's an array without buffering the entire stream
	buf := make([]byte, 1)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return false, nil, err
	}
	if n == 0 {
		return false, stream, nil
	}

	isArr := buf[0] == '['
	// Reconstruct the stream so the first peeked byte isn't lost
	return isArr, io.MultiReader(bytes.NewReader(buf[:n]), stream), nil
}

func StreamNetflow(stream io.Reader, processFn func(models.NetflowRecord)) error {
	isArr, reader, err := isArray(stream)
	if err != nil {
		return err
	}

	numWorkers := utils.OptimalWorkerCount()

	chunksChan := make(chan []byte, numWorkers*2)
	resultsChan := make(chan result, numWorkers*2)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup

	if isArr {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go processJsonArray(chunksChan, resultsChan, &wg)
		}
		go readJsonArray(reader, chunksChan, errChan)
	} else {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go processJsonLines(chunksChan, resultsChan, &wg)
		}
		go readJsonLines(reader, chunksChan, errChan)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
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

func wrapAndDecode(chunk []byte) ([]models.NetflowRecord, []byte, error) {
	cleanChunk := bytes.Trim(bytes.TrimSpace(chunk), "[], \n\r\t")
	if len(cleanChunk) == 0 {
		return nil, nil, nil
	}

	wrapped := make([]byte, 0, len(cleanChunk)+2)
	wrapped = append(wrapped, '[')
	wrapped = append(wrapped, cleanChunk...)
	wrapped = append(wrapped, ']')

	var records []models.NetflowRecord
	decoder := json.NewDecoder(bytes.NewReader(wrapped))

	if err := decoder.Decode(&records); err != nil {
		return nil, wrapped, err
	}
	return records, nil, nil
}

func processJsonArray(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		records, wrapped, err := wrapAndDecode(chunk)
		if err != nil && len(wrapped) > 0 {
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

		if records != nil {
			resultsChan <- result{records: records}
		}
	}
}

func processJsonLines(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for chunk := range chunksChan {
		records, _, err := wrapAndDecode(chunk)
		if err != nil {
			// For resilient NDJSON, fallback to line-by-line parsing of this chunk
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

		if records != nil {
			resultsChan <- result{records: records}
		}
	}
}

func readJsonArray(reader io.Reader, chunksChan chan<- []byte, errChan chan<- error) {
	readjsonByDelimiter(reader, chunksChan, errChan, '}')
}

func readJsonLines(reader io.Reader, chunksChan chan<- []byte, errChan chan<- error) {
	readjsonByDelimiter(reader, chunksChan, errChan, '\n')
}

func readjsonByDelimiter(reader io.Reader, chunksChan chan<- []byte, errChan chan<- error, delimiter byte) {
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
		idx := bytes.LastIndexByte(chunkBuf[:total], delimiter)

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
}
