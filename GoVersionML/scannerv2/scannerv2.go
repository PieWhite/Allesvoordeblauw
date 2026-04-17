package scannerv2

import (
	"bufio"
	"io"

	"goversion/models"
	"goversion/utils"
	"sync"
)

type result struct {
	records models.NDJsonRecord
	err     error
}

var pool sync.Pool = sync.Pool{
	New: func() any {
		return &models.NDJsonRecord{}
	},
}

func StreamNetflowV2(stream io.Reader, processFn func([]models.NDJsonRecord)) error {

	numWorkers := utils.OptimalWorkerCount()

	chunksChan := make(chan []byte, numWorkers*2)
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
	var wgResults sync.WaitGroup

	for res := range resultsChan {

		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		wgResults.Add(1)
		go func(records []models.NDJsonRecord) {
			processFn(records)
			wgResults.Done()
		}(res.records)
	}

}

func Producer(reader io.Reader, chunksChan chan<- []byte, errChan chan<- error) {
	defer close(chunksChan)

	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {

		raw := scanner.Bytes()

		bCopy := make([]byte, len(raw)) // TODO later checken of dit wel nodig is
		copy(bCopy, raw)

		chunksChan <- bCopy
	}

	if err := scanner.Err(); err != nil {
		errChan <- err
	}
}

func Worker(chunksChan <-chan []byte, resultsChan chan<- result, wg *sync.WaitGroup) {

	defer wg.Done()
	for rawBytes := range chunksChan {

		var record models.NDJsonRecord

		err := record.UnmarshalJSON(rawBytes)

		resultsChan <- result{records: record, err: err}
	}

}
