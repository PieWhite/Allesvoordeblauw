/*
Package tui_test provides tests for the Pencilgon terminal user interface.

This file verifies helper sizing and formatting utilities.
*/
package tui

import "testing"

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
	}

	for _, tt := range tests {
		if result := formatSize(tt.bytes); result != tt.expected {
			t.Errorf("formatSize(%d) = %q, expected %q", tt.bytes, result, tt.expected)
		}
	}
}
