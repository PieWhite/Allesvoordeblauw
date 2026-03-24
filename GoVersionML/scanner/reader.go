package scanner

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

const chunkSize = 16 * 1024 * 1024

var chunkPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, chunkSize)
		return &b
	},
}

func returnChunkToPool(chunk []byte) {
	if cap(chunk) == chunkSize {
		b := chunk[:chunkSize]
		chunkPool.Put(&b)
	}
}

func readjsonByDelimiter(reader io.Reader, chunksChan chan<- []byte, errChan chan<- error, delimiter byte) {
	defer close(chunksChan)

	var leftover []byte

	for {
		bufPtr := chunkPool.Get().(*[]byte)
		chunkBuf := *bufPtr

		copied := copy(chunkBuf, leftover)

		n, err := io.ReadFull(reader, chunkBuf[copied:])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			chunkPool.Put(bufPtr)
			errChan <- fmt.Errorf("read error: %w", err)
			return
		}

		total := copied + n
		if total == 0 {
			chunkPool.Put(bufPtr)
			break
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			chunksChan <- chunkBuf[:total]
			break
		}

		idx := bytes.LastIndexByte(chunkBuf[:total], delimiter)

		if idx == -1 {
			chunkPool.Put(bufPtr)
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
