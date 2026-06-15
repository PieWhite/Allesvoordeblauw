package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"goversion/models"
	"goversion/utils"
)

// CSVHeaderMap holds the mapped index of each required column in the nfdump CSV output.
// Unmapped columns are set to -1.
type CSVHeaderMap struct {
	tsIndex   int // first
	teIndex   int // last
	saIndex   int // src4_addr
	daIndex   int // dst4_addr
	spIndex   int // src_port
	dpIndex   int // dst_port
	prIndex   int // proto
	flgIndex  int // tcp_flags
	ipktIndex int // in_packets
	ibytIndex int // in_bytes
}

// parseCSVHeader dynamically maps CSV header columns to their index positions.
func parseCSVHeader(header []byte) CSVHeaderMap {
	m := CSVHeaderMap{
		tsIndex:   -1,
		teIndex:   -1,
		saIndex:   -1,
		daIndex:   -1,
		spIndex:   -1,
		dpIndex:   -1,
		prIndex:   -1,
		flgIndex:  -1,
		ipktIndex: -1,
		ibytIndex: -1,
	}

	colIdx := 0
	start := 0
	for i := 0; i <= len(header); i++ {
		if i == len(header) || header[i] == ',' {
			name := bytes.TrimSpace(header[start:i])
			switch {
			case bytes.Equal(name, []byte("ts")):
				m.tsIndex = colIdx
			case bytes.Equal(name, []byte("te")):
				m.teIndex = colIdx
			case bytes.Equal(name, []byte("sa")):
				m.saIndex = colIdx
			case bytes.Equal(name, []byte("da")):
				m.daIndex = colIdx
			case bytes.Equal(name, []byte("sp")):
				m.spIndex = colIdx
			case bytes.Equal(name, []byte("dp")):
				m.dpIndex = colIdx
			case bytes.Equal(name, []byte("pr")):
				m.prIndex = colIdx
			case bytes.Equal(name, []byte("flg")):
				m.flgIndex = colIdx
			case bytes.Equal(name, []byte("ipkt")):
				m.ipktIndex = colIdx
			case bytes.Equal(name, []byte("ibyt")):
				m.ibytIndex = colIdx
			}
			start = i + 1
			colIdx++
		}
	}
	return m
}

// parseUintBytes parses a uint64 value directly from a byte slice with zero allocations.
func parseUintBytes(b []byte) (uint64, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return 0, nil
	}
	var val uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid digit: %c", c)
		}
		val = val*10 + uint64(c-'0')
	}
	return val, nil
}

// parseProtoBytes maps a protocol byte slice to its numeric identifier without allocations.
func parseProtoBytes(b []byte) int {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return 0
	}
	// Try parsing numeric protocol ID first
	if b[0] >= '0' && b[0] <= '9' {
		val, err := parseUintBytes(b)
		if err == nil {
			return int(val)
		}
	}
	// Case-insensitive matching for standard protocols
	if bytes.EqualFold(b, []byte("TCP")) {
		return 6
	}
	if bytes.EqualFold(b, []byte("UDP")) {
		return 17
	}
	if bytes.EqualFold(b, []byte("ICMP")) {
		return 1
	}
	return 0
}

// parseCSVLine populates a NetflowRecord from a single CSV line based on column indices.
func parseCSVLine(line []byte, record *models.NetflowRecord, headerMap CSVHeaderMap) error {
	colIdx := 0
	start := 0

	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ',' {
			cell := line[start:i]

			switch colIdx {
			case headerMap.tsIndex:
				record.First = string(cell)
			case headerMap.teIndex:
				record.Last = string(cell)
			case headerMap.saIndex:
				record.Src4Addr = string(cell)
			case headerMap.daIndex:
				record.Dst4Addr = string(cell)
			case headerMap.flgIndex:
				record.TCPFlags = string(cell)
			case headerMap.spIndex:
				val, err := parseUintBytes(cell)
				if err != nil {
					return fmt.Errorf("invalid src port: %w", err)
				}
				record.SrcPort = int(val)
			case headerMap.dpIndex:
				val, err := parseUintBytes(cell)
				if err != nil {
					return fmt.Errorf("invalid dst port: %w", err)
				}
				record.DstPort = int(val)
			case headerMap.ipktIndex:
				val, err := parseUintBytes(cell)
				if err != nil {
					return fmt.Errorf("invalid packets: %w", err)
				}
				record.InPackets = int64(val)
			case headerMap.ibytIndex:
				val, err := parseUintBytes(cell)
				if err != nil {
					return fmt.Errorf("invalid bytes: %w", err)
				}
				record.InBytes = int64(val)
			case headerMap.prIndex:
				record.Proto = parseProtoBytes(cell)
			}

			start = i + 1
			colIdx++
		}
	}
	return nil
}

// StreamCSV streams and processes nfdump CSV logs concurrently.
func StreamCSV(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	numWorkers := utils.OptimalWorkerCount()

	scanner := bufio.NewScanner(stream)
	// Allocate a robust 64KB initial buffer, up to 10MB maximum line width
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	// Scan the first line for headers
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return nil // EOF/empty file
	}

	headerLine := scanner.Bytes()
	headerMap := parseCSVHeader(headerLine)

	var firstLine []byte
	hasAnyMatched := headerMap.tsIndex != -1 || headerMap.teIndex != -1 || headerMap.saIndex != -1 ||
		headerMap.daIndex != -1 || headerMap.spIndex != -1 || headerMap.dpIndex != -1 ||
		headerMap.prIndex != -1 || headerMap.flgIndex != -1 || headerMap.ipktIndex != -1 ||
		headerMap.ibytIndex != -1

	if !hasAnyMatched {
		// Use default nfdump CSV column mapping
		headerMap = CSVHeaderMap{
			tsIndex:   0,
			teIndex:   1,
			saIndex:   3,
			daIndex:   4,
			spIndex:   5,
			dpIndex:   6,
			prIndex:   7,
			flgIndex:  8,
			ipktIndex: 11,
			ibytIndex: 12,
		}
		// Treat the first line (read as header) as the first data line instead
		firstLine = make([]byte, len(headerLine))
		copy(firstLine, headerLine)
	}

	chunksChan := make(chan *Batch, numWorkers*2)
	resultsChan := make(chan workerResult, numWorkers*2)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup
	var hasError atomic.Bool

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go CSVWorker(chunksChan, resultsChan, &wg, &hasError, headerMap)
	}

	go CSVProducer(scanner, firstLine, chunksChan, errChan, &hasError)

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
				processFn(*nextRes.records)
			}

			if nextRes.records != nil {
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

	// Drain pendingResults in order at shutdown, treating missing sequence numbers as empty batches
	for len(pendingResults) > 0 {
		nextRes, found := pendingResults[expectedSeq]
		if found {
			delete(pendingResults, expectedSeq)

			if nextRes.err != nil && firstErr == nil {
				firstErr = nextRes.err
			}

			if nextRes.records != nil && len(*nextRes.records) > 0 {
				processFn(*nextRes.records)
			}

			if nextRes.records != nil {
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

// CSVProducer tokenizes the raw file stream line-by-line, utilizing batch memory arenas, and publishes chunks.
func CSVProducer(scanner *bufio.Scanner, firstLine []byte, chunksChan chan<- *Batch, errChan chan<- error, hasError *atomic.Bool) {
	defer close(chunksChan)

	const batchSize = 1000

	batch := batchPool.Get().(*Batch)
	batch.Lines = batch.Lines[:0]
	batch.Offset = 0
	batch.Sequence = 0

	var seq int

	appendLine := func(raw []byte) {
		// Skip empty entries
		if len(raw) == 0 {
			return
		}

		// Skip nfdump summary footer lines and short/invalid lines
		if bytes.HasPrefix(raw, []byte("Summary")) ||
			bytes.HasPrefix(raw, []byte("Time window")) ||
			bytes.HasPrefix(raw, []byte("Total bytes")) ||
			bytes.HasPrefix(raw, []byte("flows,")) {
			return
		}

		if bytes.Count(raw, []byte{','}) < 6 {
			return
		}

		// Arena growth boundary check
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

	if len(firstLine) > 0 {
		appendLine(firstLine)
	}

	for scanner.Scan() {
		if hasError.Load() {
			break
		}
		appendLine(scanner.Bytes())
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

// CSVWorker consumes batches, tokenizes columns on byte slices, parses fields, and maps them to pooled record slices.
func CSVWorker(chunksChan <-chan *Batch, resultsChan chan<- workerResult, wg *sync.WaitGroup, hasError *atomic.Bool, headerMap CSVHeaderMap) {
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
			if len(rawBytes) == 0 {
				continue
			}

			var record models.NetflowRecord
			if err := parseCSVLine(rawBytes, &record, headerMap); err != nil {
				if firstErr == nil {
					firstErr = err
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
			batchPool.Put(batch)
		}
	}
}
