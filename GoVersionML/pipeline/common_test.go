package pipeline

import (
	"io"
	"strings"
	"testing"
)

func TestProgressReader(t *testing.T) {
	t.Run("OnProgress Callback Invoked", func(t *testing.T) {
		input := "hello world"
		src := strings.NewReader(input)
		var progressBytes int64 = 0

		pr := &ProgressReader{
			r: src,
			OnProgress: func(n int64) {
				progressBytes += n
			},
		}

		buf := make([]byte, 5)
		n, err := pr.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error reading: %v", err)
		}
		if n != 5 {
			t.Errorf("expected to read 5 bytes, read %d", n)
		}
		if string(buf) != "hello" {
			t.Errorf("expected 'hello', got %q", string(buf))
		}
		if progressBytes != 5 {
			t.Errorf("expected progressBytes to be 5, got %d", progressBytes)
		}

		// Read the rest
		n, err = pr.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("unexpected error reading: %v", err)
		}
		if n != 5 {
			t.Errorf("expected to read 5 bytes, read %d", n)
		}
		if string(buf) != " worl" {
			t.Errorf("expected ' worl', got %q", string(buf))
		}
		if progressBytes != 10 {
			t.Errorf("expected progressBytes to be 10, got %d", progressBytes)
		}
	})

	t.Run("Nil OnProgress Callback Ignored", func(t *testing.T) {
		input := "test"
		src := strings.NewReader(input)

		pr := &ProgressReader{
			r:          src,
			OnProgress: nil,
		}

		buf := make([]byte, 4)
		n, err := pr.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 4 {
			t.Errorf("expected 4 bytes read, got %d", n)
		}
	})
}
