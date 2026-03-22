package scanner

import (
	"bufio"
	"fmt"
	"io"

	"github.com/goccy/go-json"

	"goversion/models"
)

func StreamNetflow(stream io.Reader, processFn func(models.NetflowRecord)) error {
	// We use a buffered scanner to read line-by-line
	// This is much more resilient than a raw JSON decoder for 'dirty' data
	reader := bufio.NewReader(stream)

	// Check if it starts with an array bracket
	peek, _ := reader.Peek(1)
	if len(peek) > 0 && peek[0] == '[' {
		return streamJSONArray(reader, processFn)
	}

	// Otherwise, treat as Line-Delimited JSON (NDJSON)
	return streamNDJSON(reader, processFn)
}

func streamJSONArray(r io.Reader, processFn func(models.NetflowRecord)) error {
	decoder := json.NewDecoder(r)
	if _, err := decoder.Token(); err != nil {
		return err
	} // Skip '['

	for decoder.More() {
		var record models.NetflowRecord
		if err := decoder.Decode(&record); err != nil {
			// In an array, we MUST stop here to avoid infinite loops
			return fmt.Errorf("json array corruption: %w", err)
		}
		processFn(record)
	}
	return nil
}

func streamNDJSON(r io.Reader, processFn func(models.NetflowRecord)) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue // Skip empty lines
		}

		var record models.NetflowRecord
		if err := json.Unmarshal(line, &record); err != nil {
			// ARCHITECTURE WIN:
			// Because we are line-based, a failure here doesn't break the 'eye'
			// of the reader. We just log and move to the next physical line.
			fmt.Printf("Skipping malformed NDJSON line: %v\n", err)
			continue
		}
		processFn(record)
	}

	return scanner.Err()
}
