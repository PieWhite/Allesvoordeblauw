package NDJSONScanner

import (
	"bufio"
	"io"
	"sync"

	"goversion/models"
	"goversion/utils"
)



type Batch struct {
	Lines  [][]byte
	Arena  []byte
	Offset int
}

// Pool for Batches to avoid allocation every batch
var batchPool = sync.Pool{
	New: func() interface{} {
		return &Batch{
			Lines:  make([][]byte, 0, 1000),
			Arena:  make([]byte, 2*1024*1024), // 2MB initial arena
			Offset: 0,
		}
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

	// Use pointers for channel communication to avoid copying
	chunksChan := make(chan *Batch, numWorkers*2)
	resultsChan := make(chan models.ScanResult, numWorkers*2)
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
		// 1. Track the first error encountered, but do NOT halt or skip the iteration.
		if res.Err != nil && firstErr == nil {
			firstErr = res.Err
		}

		// 2. If the worker parsed ANY valid records (even if an error also occurred in this batch), process them.
		if res.Records != nil && len(*res.Records) > 0 {
			processFn(*res.Records)
		}

		// 3. Always recycle the slice back into the pool to prevent memory leaks.
		if res.Records != nil {
			recordsPtr := res.Records
			// IMPORTANT: If processFn spins off a goroutine that keeps res.records,
			// you cannot pool it here! In that case, processFn must copy it or pool it itself.
			*recordsPtr = (*recordsPtr)[:0]
			recordsPool.Put(recordsPtr)
		}
	}

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}

func Producer(reader io.Reader, chunksChan chan<- *Batch, errChan chan<- error) {
	defer close(chunksChan)

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	const batchSize = 1000

	batch := batchPool.Get().(*Batch)
	batch.Lines = batch.Lines[:0]
	batch.Offset = 0

	for scanner.Scan() {
		raw := scanner.Bytes()

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

	if len(batch.Lines) > 0 {
		chunksChan <- batch
	}

	// Always send to errChan to prevent deadlocks!
	errChan <- scanner.Err()
}

func Worker(chunksChan <-chan *Batch, resultsChan chan<- models.ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for batch := range chunksChan {
		recordsPtr := recordsPool.Get().(*[]models.NetflowRecord)
		records := *recordsPtr
		records = records[:0]

		var firstErr error

		for _, rawBytes := range batch.Lines {
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
			resultsChan <- models.ScanResult{Records: recordsPtr, Err: firstErr}
		} else {
			// If empty and no error, return the pointer to the pool to prevent leaks
			recordsPool.Put(recordsPtr)
		}

		// Return batch back to pool
		batchPool.Put(batch)
	}
}
