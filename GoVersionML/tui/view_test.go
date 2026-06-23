/*
Package tui_test provides tests for the Pencilgon terminal user interface.

This file verifies UI layout view rendering outputs.
*/
package tui

import (
	"strings"
	"testing"
)

func TestModel_View(t *testing.T) {
	m := NewModel()
	view := m.View()
	if view == "" {
		t.Error("expected non-empty view")
	}

	expectations := []string{
		"Welcome to \"Pencilgon\"",
		"Single file detection",
		"Folder detection",
		"Configuration",
	}

	for _, expected := range expectations {
		if !strings.Contains(view, expected) {
			t.Errorf("expected view to contain %q, got: %s", expected, view)
		}
	}

	m.quitting = true
	if quitView := m.View(); !strings.Contains(quitView, "Goodbye from Pencilgon!") {
		t.Errorf("expected quit view to contain goodbye message, got: %s", quitView)
	}
}
