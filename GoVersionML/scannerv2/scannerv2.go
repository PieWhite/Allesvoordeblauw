package scannerv2

import (
	"bufio"
	"io"
	"sync"

	"goversion/models"
	"goversion/utils"
)

type result struct {
	records *[]models.NetflowRecord
	err     error
}

// Pool for [][]byte to avoid slice allocation every batch
var batchBytesPool = sync.Pool{
	New: func() interface{} {
		b := make([][]byte, 0, 1000)
		return &b
	},
}

// Pool for []models.NetflowRecord to avoid slice allocation every batch
var recordsPool = sync.Pool{
	New: func() interface{} {
		r := make([]models.NetflowRecord, 0, 1000)
		return &r
	},
}

func StreamNetflowV2(stream io.Reader, processFn func([]models.NetflowRecord)) error {

	numWorkers := utils.OptimalWorkerCount()

	// Use pointers to slices for channel communication to avoid copying slice headers
	chunksChan := make(chan *[][]byte, numWorkers*2)
	resultsChan := make(chan result, numWorkers*2)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go Worker(chunksChan, resultsChan, &wg)
	}
	go Producer(stream, chunksChan, errChan)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var firstErr error

	for res := range resultsChan {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}

		// Process synchronously. This caps memory since we only process what has finished parsing.
		// Dereference the pointer to pass the slice to processFn
		processFn(*res.records)

		// Return slice to pool to be recycled by workers
		// IMPORTANT: If processFn spins off a goroutine that keeps res.records,
		// you cannot pool it here! In that case, processFn must copy it or pool it itself.
		recordsPtr := res.records
		*recordsPtr = (*recordsPtr)[:0]
		recordsPool.Put(recordsPtr)
	}

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}

func Producer(reader io.Reader, chunksChan chan<- *[][]byte, errChan chan<- error) {
	defer close(chunksChan)

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	const batchSize = 1000

	batchPtr := batchBytesPool.Get().(*[][]byte)
	batch := *batchPtr
	batch = batch[:0]

	for scanner.Scan() {
		raw := scanner.Bytes()
		bCopy := make([]byte, len(raw)) // NOTE: This still allocates per line. For zero-allocation, a chunked byte arena is needed.
		copy(bCopy, raw)
		batch = append(batch, bCopy)

		if len(batch) >= batchSize {
			*batchPtr = batch
			chunksChan <- batchPtr

			batchPtr = batchBytesPool.Get().(*[][]byte)
			batch = *batchPtr
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		*batchPtr = batch
		chunksChan <- batchPtr
	}

	// Always send to errChan to prevent deadlocks!
	errChan <- scanner.Err()
}

func Worker(chunksChan <-chan *[][]byte, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()

	for batchPtr := range chunksChan {
		batch := *batchPtr

		recordsPtr := recordsPool.Get().(*[]models.NetflowRecord)
		records := *recordsPtr
		records = records[:0]

		var firstErr error

		for _, rawBytes := range batch {
			var record models.NetflowRecord
			if err := record.UnmarshalJSON(rawBytes); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			records = append(records, record)
		}

		if len(records) > 0 || firstErr != nil {
			*recordsPtr = records // Update the slice header in the pointer
			resultsChan <- result{records: recordsPtr, err: firstErr}
		} else {
			// If empty and no error, return the pointer to the pool to prevent leaks
			recordsPool.Put(recordsPtr)
		}

		// Return batch byte slice to pool
		*batchPtr = batch[:0]
		batchBytesPool.Put(batchPtr)
	}
}
