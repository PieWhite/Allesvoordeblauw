package scanner

import (
	"bytes"
	"io"
	"sync"

	"goversion/models"
	"goversion/utils"
)

type result struct {
	records []models.NetflowRecord
	err     error
}

func isArray(stream io.Reader) (bool, io.Reader, error) {
	buf := make([]byte, 1)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return false, nil, err
	}
	if n == 0 {
		return false, stream, nil
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
		readjsonByDelimiter(reader, chunksChan, errChan, '}')
	} else {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go processJsonLines(chunksChan, resultsChan, &wg)
		}
		readjsonByDelimiter(reader, chunksChan, errChan, '\n')
	}

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
		processFn(res.records)
	}

	if readerErr := <-errChan; readerErr != nil && firstErr == nil {
		firstErr = readerErr
	}

	return firstErr
}
