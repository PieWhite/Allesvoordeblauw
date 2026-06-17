package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"goversion/models"
)

type ChunkRange struct {
	Start int64
	End   int64
}

// ParallelStreamCSV scans a CSV file concurrently in N chunks using seek/read.
func ParallelStreamCSV(path string, headerLine []byte, processFn func(workerID int, records []models.NetflowRecord)) error {
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	size := info.Size()

	// Parse CSV header once
	var headerMap CSVHeaderMap
	var dataStartOffset int64
	if len(headerLine) == 0 {
		// Read the first line of the file to get headers
		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			headerLine = scanner.Bytes()
		}
	}
	headerMap = parseCSVHeader(headerLine)

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
		headerMap.InitColMap()
		dataStartOffset = 0
	} else {
		dataStartOffset = int64(len(headerLine)) + 1 // +1 for newline
	}

	usableStart := dataStartOffset
	usableSize := size - usableStart
	if usableSize <= 0 {
		return nil // File is empty or has only headers
	}

	chunkSize := usableSize / int64(numWorkers)
	if chunkSize == 0 {
		chunkSize = usableSize
		numWorkers = 1
	}

	var chunks []ChunkRange
	var current = usableStart
	for i := 0; i < numWorkers; i++ {
		start := current
		end := current + chunkSize
		if i == numWorkers-1 || end > size {
			end = size
		}
		chunks = append(chunks, ChunkRange{Start: start, End: end})
		current = end
	}

	var wg sync.WaitGroup
	errs := make([]error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int, chunk ChunkRange) {
			defer wg.Done()
			errs[workerID] = scanCSVChunk(path, chunk, workerID, workerID == 0, headerMap, processFn)
		}(i, chunks[i])
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return nil
}

func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return *(*string)(unsafe.Pointer(&b))
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

func parseCSVLineBytesUnsafe(rawBytes []byte, headerMap CSVHeaderMap) (models.NetflowRecord, bool) {
	rawBytes = bytes.TrimSpace(rawBytes)
	if len(rawBytes) == 0 {
		return models.NetflowRecord{}, false
	}
	// Skip nfdump summary footer lines and short/invalid lines
	if bytes.HasPrefix(rawBytes, []byte("Summary")) ||
		bytes.HasPrefix(rawBytes, []byte("Time window")) ||
		bytes.HasPrefix(rawBytes, []byte("Total bytes")) ||
		bytes.HasPrefix(rawBytes, []byte("flows,")) {
		return models.NetflowRecord{}, false
	}
	if bytes.Count(rawBytes, []byte{','}) < 6 {
		return models.NetflowRecord{}, false
	}
	var record models.NetflowRecord
	if err := parseCSVLineUnsafe(rawBytes, &record, headerMap); err != nil {
		return models.NetflowRecord{}, false
	}
	return record, true
}

func scanCSVChunk(path string, chunk ChunkRange, workerID int, isFirst bool, headerMap CSVHeaderMap, processFn func(workerID int, records []models.NetflowRecord)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := info.Size()

	start := chunk.Start
	if !isFirst {
		// Seek to start-1 to check if we landed exactly on a newline
		_, err = file.Seek(start-1, io.SeekStart)
		if err != nil {
			return err
		}

		var b [1]byte
		_, err = file.Read(b[:])
		if err != nil {
			return err
		}

		if b[0] != '\n' {
			// We landed in the middle of a line. Scan forward to find the next newline.
			r := bufio.NewReader(file)
			line, err := r.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					return nil // Chunk is empty
				}
				return err
			}
			start += int64(len(line))
		}
	}

	currentOffset := start
	const batchSize = 1000
	const blockSize = 16 * 1024 * 1024 // 16 MB

	// Local helper to execute the progress callback
	reportProgress := func(n int64) {
		if pw := progressRegistry.Load(); pw != nil && pw.cb != nil {
			pw.cb(n)
		}
	}

	for currentOffset < chunk.End {
		_, err = file.Seek(currentOffset, io.SeekStart)
		if err != nil {
			return err
		}

		toRead := chunk.End - currentOffset
		if toRead > blockSize {
			toRead = blockSize
		}

		buf := make([]byte, toRead)
		n, err := io.ReadFull(file, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		buf = buf[:n]

		if len(buf) == 0 {
			break
		}

		// If we didn't end with a newline and we are not at the end of the file,
		// read until the next newline and append to buf.
		if buf[len(buf)-1] != '\n' && currentOffset+int64(len(buf)) < fileSize {
			_, err = file.Seek(currentOffset+int64(len(buf)), io.SeekStart)
			if err != nil {
				return err
			}

			var extraSlice []byte
			for {
				var single [1]byte
				_, readErr := file.Read(single[:])
				if readErr != nil {
					break
				}
				extraSlice = append(extraSlice, single[0])
				if single[0] == '\n' {
					break
				}
			}
			buf = append(buf, extraSlice...)
		}

		bytesRead := int64(len(buf))

		records := make([]models.NetflowRecord, 0, batchSize)
		startIdx := 0
		for i := 0; i < len(buf); i++ {
			if buf[i] == '\n' {
				line := buf[startIdx:i]
				startIdx = i + 1

				record, ok := parseCSVLineBytesUnsafe(line, headerMap)
				if ok {
					records = append(records, record)
					if len(records) >= batchSize {
						if OnRecordsDecoded != nil {
							OnRecordsDecoded(int64(len(records)))
						}
						processFn(workerID, records)
						records = make([]models.NetflowRecord, 0, batchSize)
					}
				}
			}
		}

		if startIdx < len(buf) {
			line := buf[startIdx:]
			record, ok := parseCSVLineBytesUnsafe(line, headerMap)
			if ok {
				records = append(records, record)
			}
		}

		if len(records) > 0 {
			if OnRecordsDecoded != nil {
				OnRecordsDecoded(int64(len(records)))
			}
			processFn(workerID, records)
		}

		currentOffset += bytesRead
		reportProgress(bytesRead)
	}

	return nil
}

type progressWrapper struct {
	cb func(int64)
}

// Global atomic registry to store the progress callback without circular package dependencies
var progressRegistry atomic.Pointer[progressWrapper]

func RegisterProgressCallback(cb func(int64)) {
	if cb == nil {
		progressRegistry.Store(nil)
	} else {
		progressRegistry.Store(&progressWrapper{cb: cb})
	}
}

// ParallelStreamCSVToChannel scans a CSV file concurrently and streams NetflowRecord batches to a channel.
func ParallelStreamCSVToChannel(path string, headerLine []byte, out chan<- []models.NetflowRecord) error {
	return ParallelStreamCSV(path, headerLine, func(workerID int, records []models.NetflowRecord) {
		out <- records
	})
}
