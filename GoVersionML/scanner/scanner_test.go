package scanner

import (
	"strings"
	"testing"

	"goversion/models"
)

func TestStreamNetflow(t *testing.T) {
	t.Run("Valid JSON Array", func(t *testing.T) {
		input := `[{"src4_addr": "1.2.3.4"}, {"src4_addr": "5.6.7.8"}]`
		r := strings.NewReader(input)

		var count int
		err := StreamNetflow(r, func(record models.NetflowRecord) {
			count++
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
		err := StreamNetflow(r, func(record models.NetflowRecord) {
			count++
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
		// Note: No opening [ and no commas between objects.
		input := `{"src4_addr": "1.1.1.1"}
{"broken": ---}
{"src4_addr": "2.2.2.2"}`

		r := strings.NewReader(input)
		var count int
		err := StreamNetflow(r, func(record models.NetflowRecord) {
			count++
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
		err := StreamNetflow(r, func(record models.NetflowRecord) {})
		if err != nil {
			t.Errorf("Empty input should not error, got %v", err)
		}
	})
}
