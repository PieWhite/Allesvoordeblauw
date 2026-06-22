// Package scanner handles raw file stream processing and parsing of netflow CSV records.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"goversion/models"
	"goversion/utils"
)

const (
	colIgnore = iota
	colFirst
	colLast
	colSrc4Addr
	colDst4Addr
	colTCPFlags
	colSrcPort
	colDstPort
	colInPackets
	colInBytes
	colProto
)

type CSVHeaderMap struct {
	tsIndex   int
	teIndex   int
	saIndex   int
	daIndex   int
	spIndex   int
	dpIndex   int
	prIndex   int
	flgIndex  int
	ipktIndex int
	ibytIndex int

	colMap []int
}

func (m *CSVHeaderMap) InitColMap() {
	maxIdx := -1
	idxs := []int{m.tsIndex, m.teIndex, m.saIndex, m.daIndex, m.spIndex, m.dpIndex, m.prIndex, m.flgIndex, m.ipktIndex, m.ibytIndex}
	for _, idx := range idxs {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	if maxIdx < 0 {
		return
	}
	m.colMap = make([]int, maxIdx+1)
	for i := range m.colMap {
		m.colMap[i] = colIgnore
	}
	if m.tsIndex >= 0 {
		m.colMap[m.tsIndex] = colFirst
	}
	if m.teIndex >= 0 {
		m.colMap[m.teIndex] = colLast
	}
	if m.saIndex >= 0 {
		m.colMap[m.saIndex] = colSrc4Addr
	}
	if m.daIndex >= 0 {
		m.colMap[m.daIndex] = colDst4Addr
	}
	if m.flgIndex >= 0 {
		m.colMap[m.flgIndex] = colTCPFlags
	}
	if m.spIndex >= 0 {
		m.colMap[m.spIndex] = colSrcPort
	}
	if m.dpIndex >= 0 {
		m.colMap[m.dpIndex] = colDstPort
	}
	if m.ipktIndex >= 0 {
		m.colMap[m.ipktIndex] = colInPackets
	}
	if m.ibytIndex >= 0 {
		m.colMap[m.ibytIndex] = colInBytes
	}
	if m.prIndex >= 0 {
		m.colMap[m.prIndex] = colProto
	}
}

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
	m.InitColMap()
	return m
}

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

func parseProtoBytes(b []byte) int {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return 0
	}
	if b[0] >= '0' && b[0] <= '9' {
		val, err := parseUintBytes(b)
		if err == nil {
			return int(val)
		}
	}
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

func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

func parseCSVLineUnsafe(line []byte, record *models.NetflowRecord, headerMap CSVHeaderMap) error {
	colIdx := 0
	start := 0
	numCols := len(headerMap.colMap)

	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ',' {
			if colIdx < numCols {
				target := headerMap.colMap[colIdx]
				if target != colIgnore {
					cell := line[start:i]
					switch target {
					case colFirst:
						record.First = unsafeString(cell)
					case colLast:
						record.Last = unsafeString(cell)
					case colSrc4Addr:
						record.Src4Addr = unsafeString(cell)
					case colDst4Addr:
						record.Dst4Addr = unsafeString(cell)
					case colTCPFlags:
						record.TCPFlags = unsafeString(cell)
					case colSrcPort:
						val, err := parseUintBytes(cell)
						if err != nil {
							return fmt.Errorf("invalid src port: %w", err)
						}
						record.SrcPort = int(val)
					case colDstPort:
						val, err := parseUintBytes(cell)
						if err != nil {
							return fmt.Errorf("invalid dst port: %w", err)
						}
						record.DstPort = int(val)
					case colInPackets:
						val, err := parseUintBytes(cell)
						if err != nil {
							return fmt.Errorf("invalid packets: %w", err)
						}
						record.InPackets = int64(val)
					case colInBytes:
						val, err := parseUintBytes(cell)
						if err != nil {
							return fmt.Errorf("invalid bytes: %w", err)
						}
						record.InBytes = int64(val)
					case colProto:
						record.Proto = parseProtoBytes(cell)
					}
				}
			}

			start = i + 1
			colIdx++
		}
	}
	return nil
}

func cloneRecords(records []models.NetflowRecord) []models.NetflowRecord {
	copied := make([]models.NetflowRecord, len(records))
	for i, r := range records {
		copied[i] = r
		copied[i].First = strings.Clone(r.First)
		copied[i].Last = strings.Clone(r.Last)
		copied[i].Src4Addr = strings.Clone(r.Src4Addr)
		copied[i].Dst4Addr = strings.Clone(r.Dst4Addr)
		copied[i].TCPFlags = strings.Clone(r.TCPFlags)
	}
	return copied
}

func StreamCSV(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	numWorkers := utils.OptimalWorkerCount()

	scanner := bufio.NewScanner(stream)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return nil
	}

	headerLine := scanner.Bytes()
	headerMap := parseCSVHeader(headerLine)

	var firstLine []byte
	hasAnyMatched := headerMap.tsIndex != -1 || headerMap.teIndex != -1 || headerMap.saIndex != -1 ||
		headerMap.daIndex != -1 || headerMap.spIndex != -1 || headerMap.dpIndex != -1 ||
		headerMap.prIndex != -1 || headerMap.flgIndex != -1 || headerMap.ipktIndex != -1 ||
		headerMap.ibytIndex != -1

	if !hasAnyMatched {
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
		headerMap.InitColMap()
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

func CSVProducer(scanner *bufio.Scanner, firstLine []byte, chunksChan chan<- *Batch, errChan chan<- error, hasError *atomic.Bool) {
	defer close(chunksChan)

	const batchSize = 1000

	batch := batchPool.Get().(*Batch)
	batch.Lines = batch.Lines[:0]
	batch.Offset = 0
	batch.Sequence = 0

	var seq int

	appendLine := func(raw []byte) {
		if len(raw) == 0 {
			return
		}

		if bytes.HasPrefix(raw, []byte("Summary")) ||
			bytes.HasPrefix(raw, []byte("Time window")) ||
			bytes.HasPrefix(raw, []byte("Total bytes")) ||
			bytes.HasPrefix(raw, []byte("flows,")) {
			return
		}

		if bytes.Count(raw, []byte{','}) < 6 {
			return
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
			if err := parseCSVLineUnsafe(rawBytes, &record, headerMap); err != nil {
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
			resultsChan <- workerResult{records: nil, err: nil, batch: batch}
		}
	}
}

func RegisterProgressCallback(cb func(int64)) {}

func StreamCSVToChannel(ctx context.Context, stream io.Reader, out chan<- []models.NetflowRecord) error {
	return StreamCSV(stream, func(records []models.NetflowRecord) {
		out <- cloneRecords(records)
	})
}

func ParallelStreamCSVToChannel(path string, headerLine []byte, out chan<- []models.NetflowRecord) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return StreamCSV(file, func(records []models.NetflowRecord) {
		out <- cloneRecords(records)
	})
}

func ParallelStreamCSV(path string, headerLine []byte, processFn func(workerID int, records []models.NetflowRecord)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return StreamCSV(file, func(records []models.NetflowRecord) {
		processFn(0, cloneRecords(records))
	})
}
