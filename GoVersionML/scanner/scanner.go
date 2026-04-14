package scanner

import (
	"bufio"
	"fmt"
	"io"
	"sync"

	"github.com/mailru/easyjson/jlexer"

	"goversion/models"
	"goversion/utils"
)

func StreamNetflow(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	numWorkers := utils.OptimalWorkerCount()
	recordChan := make(chan models.NetflowRecord, 2000)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup

	// 1. Start workers to process records from the channel
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batch := make([]models.NetflowRecord, 0, 1000)
			for record := range recordChan {
				batch = append(batch, record)
				if len(batch) >= 1000 {
					processFn(batch)
					batch = batch[:0]
				}
			}
			if len(batch) > 0 {
				processFn(batch)
			}
		}()
	}

	// 2. Decoder goroutine
	go func() {
		defer close(recordChan)
		errChan <- decodeStream(stream, recordChan)
	}()

	// 3. Wait for all workers to finish
	wg.Wait()

	// 4. Return any error encountered during decoding
	return <-errChan
}

// decodeStream manually scans top-level array structure with buffered I/O,
// extracts each JSON object as raw bytes using brace-matching, and decodes
// with easyjson's generated code — zero reflection, single-pass.
func decodeStream(stream io.Reader, out chan<- models.NetflowRecord) error {
	br := bufio.NewReaderSize(stream, 256*1024) // 256KB read buffer

	// Skip whitespace and expect '['
	if err := skipWhitespace(br); err != nil {
		if err == io.EOF {
			return nil // Empty input
		}
		return fmt.Errorf("reading opening token: %w", err)
	}

	b, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("reading opening bracket: %w", err)
	}
	if b != '[' {
		return fmt.Errorf("expected '[', got '%c'", b)
	}

	// Reusable buffer for extracting individual JSON objects
	buf := make([]byte, 0, 1024)

	for {
		// Skip whitespace and commas between elements
		if err := skipWhitespace(br); err != nil {
			return fmt.Errorf("reading array element: %w", err)
		}

		// Peek to check for end of array
		b, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("reading next element: %w", err)
		}

		if b == ']' {
			return nil // End of array
		}
		if b == ',' {
			// Skip comma and continue to next element
			if err := skipWhitespace(br); err != nil {
				return fmt.Errorf("after comma: %w", err)
			}
			b, err = br.ReadByte()
			if err != nil {
				return fmt.Errorf("reading element after comma: %w", err)
			}
			if b == ']' {
				return nil // Trailing comma edge case
			}
		}

		if b != '{' {
			return fmt.Errorf("expected '{', got '%c'", b)
		}

		// Extract the full JSON object using brace-matching
		buf = buf[:0]
		buf = append(buf, '{')
		if err := extractObject(br, &buf); err != nil {
			return fmt.Errorf("extracting object: %w", err)
		}

		// Decode with easyjson — zero reflection
		var rec models.NetflowRecord
		lex := jlexer.Lexer{Data: buf}
		rec.UnmarshalEasyJSON(&lex)

		if err := lex.Error(); err != nil {
			return fmt.Errorf("easyjson decode: %w", err)
		}

		out <- rec
	}
}

// extractObject reads bytes from br until the matching closing '}' is found,
// handling nested braces and quoted strings correctly. The opening '{' must
// already be in buf.
func extractObject(br *bufio.Reader, buf *[]byte) error {
	depth := 1
	inString := false
	escaped := false

	for depth > 0 {
		b, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("unexpected end of object: %w", err)
		}
		*buf = append(*buf, b)

		if escaped {
			escaped = false
			continue
		}

		if b == '\\' && inString {
			escaped = true
			continue
		}

		if b == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		switch b {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return nil
}

// skipWhitespace advances the reader past whitespace characters.
func skipWhitespace(br *bufio.Reader) error {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return err
		}
		if b[0] != ' ' && b[0] != '\t' && b[0] != '\r' && b[0] != '\n' {
			return nil
		}
		br.ReadByte()
	}
}
