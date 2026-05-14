package JSONScanner

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"goversion/models"
	"goversion/utils"
)

type result struct {
	records *[]models.NetflowRecord
	err     error
}

var recordsPool = sync.Pool{
	New: func() interface{} {
		r := make([]models.NetflowRecord, 0, 1000)
		return &r
	},
}

func isArray(stream io.Reader) (bool, io.Reader, error) {
	buf := make([]byte, 1)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return false, nil, fmt.Errorf("failed to peek buffer: %w", err)
	}
	if n == 0 && err == io.EOF {
		return false, nil, fmt.Errorf("input stream is empty")
	}

	isArr := buf[0] == '['

	return isArr, io.MultiReader(bytes.NewReader(buf[:n]), stream), nil
}

func StreamNetflow(stream io.Reader, processFn func([]models.NetflowRecord)) error {
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
		go readjsonByDelimiter(reader, chunksChan, errChan, '}')
	} else {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go processJsonLines(chunksChan, resultsChan, &wg)
		}
		go readjsonByDelimiter(reader, chunksChan, errChan, '\n')
	}

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
		go func(recordsPtr *[]models.NetflowRecord) {
			processFn(*recordsPtr)

			*recordsPtr = (*recordsPtr)[:0]
			recordsPool.Put(recordsPtr)

			wgResults.Done()
		}(res.records)
	}

	wgResults.Wait()

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}
