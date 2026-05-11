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
	seq     int
}

type Batch struct {
	Lines  [][]byte
	Arena  []byte
	Offset int
	Seq    int
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
	var nextSeq int
	pending := make(map[int]result)

	for res := range resultsChan {
		// Store the result in the pending map for resequencing
		pending[res.seq] = res

		// Process as many results as we can in the correct order
		for {
			r, ok := pending[nextSeq]
			if !ok {
				break
			}
			delete(pending, nextSeq)

			// 1. Track the first error encountered, but do NOT halt or skip the iteration.
			if r.err != nil && firstErr == nil {
				firstErr = r.err
			}

			// 2. If the worker parsed ANY valid records (even if an error also occurred in this batch), process them.
			if r.records != nil && len(*r.records) > 0 {
				processFn(*r.records)
			}

			// 3. Always recycle the slice back into the pool to prevent memory leaks.
			if r.records != nil {
				recordsPtr := r.records
				*recordsPtr = (*recordsPtr)[:0]
				recordsPool.Put(recordsPtr)
			}

			nextSeq++
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
	seq := 0

	batch := batchPool.Get().(*Batch)
	batch.Lines = batch.Lines[:0]
	batch.Offset = 0
	batch.Seq = seq
	seq++

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
			batch.Seq = seq
			seq++
		}
	}

	if len(batch.Lines) > 0 {
		chunksChan <- batch
	}

	// Always send to errChan to prevent deadlocks!
	errChan <- scanner.Err()
}

func Worker(chunksChan <-chan *Batch, resultsChan chan<- result, wg *sync.WaitGroup) {
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
			resultsChan <- result{records: recordsPtr, err: firstErr, seq: batch.Seq}
		} else {
			// If empty and no error, return the pointer to the pool to prevent leaks
			recordsPool.Put(recordsPtr)
		}

		// Return batch back to pool
		batchPool.Put(batch)
	}
}
