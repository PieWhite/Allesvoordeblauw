package scanner

import (
	"bufio"
	"bytes"
	"io"
	"sync"
	"sync/atomic"

	"goversion/models"
	"goversion/utils"
)

type Batch struct {
	Lines  [][]byte
	Arena  []byte
	Offset int
}

var batchPool = sync.Pool{
	New: func() interface{} {
		return &Batch{
			Lines:  make([][]byte, 0, 1000),
			Arena:  make([]byte, 1024*1024),
			Offset: 0,
		}
	},
}

var recordsPool = sync.Pool{
	New: func() interface{} {
		r := make([]models.NetflowRecord, 0, 1000)
		return &r
	},
}

// splitJSONObjects is a custom bufio.SplitFunc that tokenises JSON objects
// bounded by '{' and '}' directly from the stream.
func splitJSONObjects(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// Find the start of the next JSON object
	start := bytes.IndexByte(data, '{')
	if start == -1 {
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	}

	// Find the matching closing brace
	end := bytes.IndexByte(data[start:], '}')
	if end == -1 {
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	}

	absoluteEnd := start + end + 1
	token = data[start:absoluteEnd]
	return absoluteEnd, token, nil
}

func StreamJSON(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	return StreamNetflow(stream, processFn, false)
}

func StreamNDJSON(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	return StreamNetflow(stream, processFn, true)
}

func StreamNetflow(stream io.Reader, processFn func([]models.NetflowRecord), isNDJSON bool) error {
	numWorkers := utils.OptimalWorkerCount()

	chunksChan := make(chan *Batch, numWorkers*2)
	resultsChan := make(chan models.ScanResult, numWorkers*2)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup
	var hasError atomic.Bool

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go Worker(chunksChan, resultsChan, &wg, isNDJSON, &hasError)
	}

	if isNDJSON {
		go Producer(stream, chunksChan, errChan, bufio.ScanLines, &hasError)
	} else {
		go Producer(stream, chunksChan, errChan, splitJSONObjects, &hasError)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var firstErr error

	for res := range resultsChan {
		if res.Err != nil && firstErr == nil {
			firstErr = res.Err
		}

		if res.Records != nil && len(*res.Records) > 0 {
			processFn(*res.Records)
		}

		if res.Records != nil {
			recordsPtr := res.Records
			*recordsPtr = (*recordsPtr)[:0]
			recordsPool.Put(recordsPtr)
		}
	}

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}

func Producer(reader io.Reader, chunksChan chan<- *Batch, errChan chan<- error, splitFn bufio.SplitFunc, hasError *atomic.Bool) {
	defer close(chunksChan)

	scanner := bufio.NewScanner(reader)
	scanner.Split(splitFn)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	const batchSize = 1000

	batch := batchPool.Get().(*Batch)
	batch.Lines = batch.Lines[:0]
	batch.Offset = 0

	for scanner.Scan() {
		if hasError.Load() {
			break
		}

		raw := scanner.Bytes()

		// Skip empty entries
		if len(raw) == 0 {
			continue
		}

		// If the current arena is too small to fit the new line, allocate a new one.
		if batch.Offset+len(raw) > len(batch.Arena) {
			newCap := len(batch.Arena) * 2
			if newCap < len(raw) {
				newCap = len(raw) * 2
			}
			batch.Arena = make([]byte, newCap)
			batch.Offset = 0
		}

		// Copy the dynamically read bytes into our pre-allocated Arena
		n := copy(batch.Arena[batch.Offset:], raw)
		batch.Lines = append(batch.Lines, batch.Arena[batch.Offset:batch.Offset+n])
		batch.Offset += n

		if len(batch.Lines) >= batchSize {
			chunksChan <- batch

			batch = batchPool.Get().(*Batch)
			batch.Lines = batch.Lines[:0]
			batch.Offset = 0
		}
	}

	if len(batch.Lines) > 0 && !hasError.Load() {
		chunksChan <- batch
	}

	errChan <- scanner.Err()
}

func Worker(chunksChan <-chan *Batch, resultsChan chan<- models.ScanResult, wg *sync.WaitGroup, isNDJSON bool, hasError *atomic.Bool) {
	defer wg.Done()

	for batch := range chunksChan {
		recordsPtr := recordsPool.Get().(*[]models.NetflowRecord)
		records := *recordsPtr
		records = records[:0]

		var firstErr error

		for _, rawBytes := range batch.Lines {
			if hasError.Load() {
				break
			}

			// Trim potential trailing comma suffixes or spaces (common in array segments or lines)
			rawBytes = bytes.TrimSpace(rawBytes)
			rawBytes = bytes.TrimSuffix(rawBytes, []byte{','})
			rawBytes = bytes.TrimSpace(rawBytes)
			if len(rawBytes) == 0 {
				continue
			}

			var record models.NetflowRecord
			if err := record.UnmarshalJSON(rawBytes); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				if isNDJSON {
					continue
				}
				hasError.Store(true)
				break
			}
			records = append(records, record)
		}

		if len(records) > 0 || firstErr != nil {
			*recordsPtr = records
			resultsChan <- models.ScanResult{Records: recordsPtr, Err: firstErr}
		} else {
			recordsPool.Put(recordsPtr)
		}

		batchPool.Put(batch)
	}
}
