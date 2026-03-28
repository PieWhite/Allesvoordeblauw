package scanner

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"testing"

	"goversion/models"
)

// A mocked reader to simulate read errors.
type errReader struct{ err error }

func (e *errReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func TestIsArray(t *testing.T) {
	t.Run("Valid JSON Array Start", func(t *testing.T) {
		r := strings.NewReader("[{}, {}]")
		isArr, reader, err := isArray(r)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !isArr {
			t.Errorf("expected isArr=true")
		}

		// Check the returned reader still contains the full data
		b, _ := io.ReadAll(reader)
		if string(b) != "[{}, {}]" {
			t.Errorf("reader corrupted: %s", string(b))
		}
	})

	t.Run("Valid NDJSON Start", func(t *testing.T) {
		r := strings.NewReader(`{"a": 1}` + "\n" + `{"b": 2}`)
		isArr, reader, err := isArray(r)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if isArr {
			t.Errorf("expected isArr=false")
		}

		b, _ := io.ReadAll(reader)
		if !strings.HasPrefix(string(b), "{") {
			t.Errorf("reader corrupted")
		}
	})

	t.Run("Empty Stream", func(t *testing.T) {
		r := strings.NewReader("")
		isArr, reader, err := isArray(r)
		if err == nil {
			t.Fatalf("expected error for empty stream, got nil")
		}
		if isArr {
			t.Errorf("expected false for empty")
		}
		if reader != nil {
			t.Errorf("expected nil reader on error")
		}
	})

	t.Run("Read Error", func(t *testing.T) {
		expectedErr := errors.New("mock read error")
		r := &errReader{err: expectedErr}
		isArr, _, err := isArray(r)
		if err == nil || !strings.Contains(err.Error(), "mock read error") {
			t.Errorf("expected wrapped mock read error, got %v", err)
		}
		if isArr {
			t.Errorf("expected isArr=false on error")
		}
	})
}

func TestStreamNetflow(t *testing.T) {
	t.Run("Valid JSON Array", func(t *testing.T) {
		input := `[{"src4_addr": "1.2.3.4"}, {"src4_addr": "5.6.7.8"}]`
		r := strings.NewReader(input)

		var count int
		err := StreamNetflow(r, func(records []models.NetflowRecord) {
			count += len(records)
		})

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 records, got %d", count)
		}
	})

	t.Run("Strict Array Failure (No Infinite Loop)", func(t *testing.T) {
		// In a JSON Array, a syntax error must stop the execution
		input := `[{"src4_addr": "1.1.1.1"}, {---}, {"src4_addr": "2.2.2.2"}]`
		r := strings.NewReader(input)

		var count int
		err := StreamNetflow(r, func(records []models.NetflowRecord) {
			count += len(records)
		})

		if err == nil {
			t.Error("Expected error for corrupted array, got nil")
		}
		if count != 1 {
			t.Errorf("Expected only 1 successful record before failure, got %d", count)
		}
	})

	t.Run("Resilient NDJSON (Skips Broken Lines)", func(t *testing.T) {
		// One record per line. Line 2 is garbage.
		input := `{"src4_addr": "1.1.1.1"}
{"broken": ---}
{"src4_addr": "2.2.2.2"}`

		r := strings.NewReader(input)
		var count int
		err := StreamNetflow(r, func(records []models.NetflowRecord) {
			count += len(records)
		})

		if err != nil {
			t.Errorf("NDJSON should handle errors internally, got %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 successful records (skipped line 2), got %d", count)
		}
	})

	t.Run("Empty Input", func(t *testing.T) {
		r := strings.NewReader("")
		err := StreamNetflow(r, func(records []models.NetflowRecord) {})
		if err == nil || err.Error() != "input stream is empty" {
			t.Errorf("Empty input should return stream empty error, got %v", err)
		}
	})

	t.Run("Read Error Initial IsArray", func(t *testing.T) {
		expectedErr := errors.New("mock read error initial")
		r := &errReader{err: expectedErr}

		err := StreamNetflow(r, func(records []models.NetflowRecord) {})
		if err == nil || !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Errorf("expected wrapped %v, got %v", expectedErr, err)
		}
	})

	t.Run("Reader ReadFull Error Mid-Stream Array", func(t *testing.T) {
		// We simulate a reader that reads one character '[' then returns an error.
		// We can do this with io.MultiReader
		mockErr := errors.New("mid-stream failure")
		r := io.MultiReader(strings.NewReader("["), &errReader{err: mockErr})

		err := StreamNetflow(r, func(records []models.NetflowRecord) {})
		// The error from the reader is captured in errChan, returning mockErr wrapped
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("mid-stream failure")) {
			t.Errorf("expected mid-stream error, got %v", err)
		}
	})

	t.Run("Reader ReadFull Error Mid-Stream NDJSON", func(t *testing.T) {
		mockErr := errors.New("mid-stream failure")
		r := io.MultiReader(strings.NewReader("{"), &errReader{err: mockErr})

		err := StreamNetflow(r, func(records []models.NetflowRecord) {})
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("mid-stream failure")) {
			t.Errorf("expected mid-stream error, got %v", err)
		}
	})
}
