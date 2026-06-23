/*
Package tui_test provides tests for the Pencilgon terminal user interface.

This file verifies initial state configuration for the TUI Model.
*/
package tui

import "testing"

func TestModel_Init(t *testing.T) {
	m := NewModel()
	if cmd := m.Init(); cmd != nil {
		t.Errorf("expected Init() to return nil, got %v", cmd)
	}
}
