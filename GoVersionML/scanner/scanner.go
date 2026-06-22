// Package scanner provides high-performance, concurrent stream-processing parsers
// for Netflow logs in JSON, NDJSON, CSV, and PCAP formats.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"

	"goversion/models"
	"goversion/utils"
)

type Batch struct {
	Lines    [][]byte
	Arena    []byte
	Offset   int
	Sequence int
}

var batchPool = sync.Pool{
	New: func() interface{} {
		return &Batch{
			Lines:    make([][]byte, 0, 1000),
			Arena:    make([]byte, 1024*1024),
			Offset:   0,
			Sequence: 0,
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

	start := bytes.IndexByte(data, '{')
	if start == -1 {
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	}

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

type workerResult struct {
	records *[]models.NetflowRecord
	err     error
	batch   *Batch
}

var OnRecordsDecoded func(delta int64)

func StreamJSON(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	return StreamNetflow(stream, processFn, false)
}

func StreamNDJSON(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	return StreamNetflow(stream, processFn, true)
}

func StreamNetflow(stream io.Reader, processFn func([]models.NetflowRecord), isNDJSON bool) error {
	numWorkers := utils.OptimalWorkerCount()

	chunksChan := make(chan *Batch, numWorkers*2)
	resultsChan := make(chan workerResult, numWorkers*2)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup
	var hasError atomic.Bool

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go Worker(chunksChan, resultsChan, &wg, isNDJSON, &hasError, nil)
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
	expectedSeq := 0
	pendingResults := make(map[int]workerResult)

	for res := range resultsChan {
		if res.batch != nil {
			pendingResults[res.batch.Sequence] = res
		}

		for {
			nextRes, found := pendingResults[expectedSeq]
			if !found {
				break
			}
			delete(pendingResults, expectedSeq)

			if nextRes.err != nil && firstErr == nil {
				firstErr = nextRes.err
			}

			if nextRes.records != nil && len(*nextRes.records) > 0 {
				if OnRecordsDecoded != nil {
					OnRecordsDecoded(int64(len(*nextRes.records)))
				}
				if processFn != nil {
					processFn(*nextRes.records)
				}
				recordsPtr := nextRes.records
				*recordsPtr = (*recordsPtr)[:0]
				recordsPool.Put(recordsPtr)
			}

			if nextRes.batch != nil {
				batchPool.Put(nextRes.batch)
			}
			expectedSeq++
		}
	}

	for len(pendingResults) > 0 {
		nextRes, found := pendingResults[expectedSeq]
		if found {
			delete(pendingResults, expectedSeq)

			if nextRes.err != nil && firstErr == nil {
				firstErr = nextRes.err
			}

			if nextRes.records != nil && len(*nextRes.records) > 0 {
				if OnRecordsDecoded != nil {
					OnRecordsDecoded(int64(len(*nextRes.records)))
				}
				if processFn != nil {
					processFn(*nextRes.records)
				}
				recordsPtr := nextRes.records
				*recordsPtr = (*recordsPtr)[:0]
				recordsPool.Put(recordsPtr)
			}

			if nextRes.batch != nil {
				batchPool.Put(nextRes.batch)
			}
		}
		expectedSeq++
	}

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}

// StreamNetflowToChannel is a backward-compatible wrapper that parses and streams NetflowRecords to a channel safely.
func StreamNetflowToChannel(ctx context.Context, stream io.Reader, out chan<- []models.NetflowRecord, isNDJSON bool) error {
	return StreamNetflow(stream, func(records []models.NetflowRecord) {
		select {
		case <-ctx.Done():
		case out <- cloneRecords(records):
		}
	}, isNDJSON)
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
	batch.Sequence = 0

	var seq int

	for scanner.Scan() {
		if hasError.Load() {
			break
		}

		raw := scanner.Bytes()

		if len(raw) == 0 {
			continue
		}

		if batch.Offset+len(raw) > len(batch.Arena) {
			newCap := len(batch.Arena) * 2
			if newCap < len(raw) {
				newCap = len(raw) * 2
			}
			batch.Arena = make([]byte, newCap)
			batch.Offset = 0
		}

		n := copy(batch.Arena[batch.Offset:], raw)
		batch.Lines = append(batch.Lines, batch.Arena[batch.Offset:batch.Offset+n])
		batch.Offset += n

		if len(batch.Lines) >= batchSize {
			batch.Sequence = seq
			seq++
			chunksChan <- batch

			batch = batchPool.Get().(*Batch)
			batch.Lines = batch.Lines[:0]
			batch.Offset = 0
		}
	}

	if len(batch.Lines) > 0 && !hasError.Load() {
		batch.Sequence = seq
		seq++
		chunksChan <- batch
	} else {
		batchPool.Put(batch)
	}

	errChan <- scanner.Err()
}

func Worker(chunksChan <-chan *Batch, resultsChan chan<- workerResult, wg *sync.WaitGroup, isNDJSON bool, hasError *atomic.Bool, processFn func([]models.NetflowRecord)) {
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
			resultsChan <- workerResult{records: recordsPtr, err: firstErr, batch: batch}
		} else {
			recordsPool.Put(recordsPtr)
			resultsChan <- workerResult{records: nil, err: nil, batch: batch}
		}
	}
}

