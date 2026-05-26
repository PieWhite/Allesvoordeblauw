package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestModel_Init(t *testing.T) {
	m := NewModel()
	cmd := m.Init()
	if cmd != nil {
		t.Errorf("expected Init() to return nil, got %v", cmd)
	}
}

func TestModel_Update_QuitKeys(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.Msg
	}{
		{
			name: "quit on 'q'",
			msg:  tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")},
		},
		{
			name: "quit on Ctrl+C",
			msg:  tea.KeyMsg{Type: tea.KeyCtrlC},
		},
		{
			name: "quit on Escape",
			msg:  tea.KeyMsg{Type: tea.KeyEsc},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel()
			updatedModel, cmd := m.Update(tt.msg)
			mResult, ok := updatedModel.(Model)
			if !ok {
				t.Fatalf("expected updated model to be of type Model")
			}
			if !mResult.quitting {
				t.Error("expected quitting state to be true")
			}
			if cmd == nil {
				t.Error("expected a non-nil quit command")
			}
		})
	}
}

func TestModel_View(t *testing.T) {
	m := NewModel()
	view := m.View()
	if view == "" {
		t.Error("expected non-empty view")
	}
	if !strings.Contains(view, "Welcome to \"Pencilgon\"") {
		t.Errorf("expected view to contain welcome message, got: %s", view)
	}

	m.quitting = true
	quitView := m.View()
	if !strings.Contains(quitView, "Goodbye from Pencilgon!") {
		t.Errorf("expected quit view to contain goodbye message, got: %s", quitView)
	}
}
