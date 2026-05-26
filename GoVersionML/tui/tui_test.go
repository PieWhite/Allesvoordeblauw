package tui

import (
	"path/filepath"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel()
			m.state = stateMenu
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
	if !strings.Contains(view, "Single file detection") {
		t.Errorf("expected view to contain Single file detection, got: %s", view)
	}
	if !strings.Contains(view, "Folder detection") {
		t.Errorf("expected view to contain Folder detection, got: %s", view)
	}

	m.quitting = true
	quitView := m.View()
	if !strings.Contains(quitView, "Goodbye from Pencilgon!") {
		t.Errorf("expected quit view to contain goodbye message, got: %s", quitView)
	}
}

func TestModel_Update_Navigation(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		startPos    int
		expectedPos int
	}{
		{
			name:        "navigate down from 0",
			key:         "down",
			startPos:    0,
			expectedPos: 1,
		},
		{
			name:        "navigate down from 1 (wrap around)",
			key:         "down",
			startPos:    1,
			expectedPos: 0,
		},
		{
			name:        "navigate up from 1",
			key:         "up",
			startPos:    1,
			expectedPos: 0,
		},
		{
			name:        "navigate up from 0 (wrap around)",
			key:         "up",
			startPos:    0,
			expectedPos: 1,
		},
		{
			name:        "navigate down with 'j'",
			key:         "j",
			startPos:    0,
			expectedPos: 1,
		},
		{
			name:        "navigate up with 'k'",
			key:         "k",
			startPos:    1,
			expectedPos: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel()
			m.cursor = tt.startPos
			
			var msg tea.Msg
			if tt.key == "down" {
				msg = tea.KeyMsg{Type: tea.KeyDown}
			} else if tt.key == "up" {
				msg = tea.KeyMsg{Type: tea.KeyUp}
			} else {
				msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)}
			}

			updatedModel, _ := m.Update(msg)
			mResult, ok := updatedModel.(Model)
			if !ok {
				t.Fatalf("expected updated model to be of type Model")
			}
			if mResult.cursor != tt.expectedPos {
				t.Errorf("expected cursor to be %d, got %d", tt.expectedPos, mResult.cursor)
			}
		})
	}
}

func TestModel_Enter_LoadsDirectory(t *testing.T) {
	m := NewModel()
	m.cursor = 0 // Single file detection

	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}

	if mResult.state != stateFileBrowser {
		t.Errorf("expected state to switch to stateFileBrowser, got %v", mResult.state)
	}

	if mResult.currentDir == "" {
		t.Error("expected currentDir to be populated")
	}

	if len(mResult.entries) == 0 {
		t.Error("expected directory entries to be loaded")
	}
}

func TestModel_FileBrowser_EscReturns(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	_ = m.loadDirectory(".")

	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}

	if mResult.state != stateMenu {
		t.Errorf("expected state to return to stateMenu, got %v", mResult.state)
	}
}

func TestModel_FileBrowser_BackspaceGoesUp(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	
	// Start in current directory
	_ = m.loadDirectory(".")
	startDir := m.currentDir

	// Navigate up one level
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}

	expectedParent := filepath.Dir(startDir)
	if mResult.currentDir != expectedParent {
		t.Errorf("expected directory to be %s, got %s", expectedParent, mResult.currentDir)
	}
}

func TestModel_FileBrowser_Navigation(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	_ = m.loadDirectory(".")
	m.fileCursor = 0

	// Go down
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}

	if mResult.fileCursor != 1 {
		t.Errorf("expected fileCursor to be 1, got %d", mResult.fileCursor)
	}

	// Go up
	updatedModel2, _ := mResult.Update(tea.KeyMsg{Type: tea.KeyUp})
	mResult2, ok := updatedModel2.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}

	if mResult2.fileCursor != 0 {
		t.Errorf("expected fileCursor to return to 0, got %d", mResult2.fileCursor)
	}
}

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
		result := formatSize(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatSize(%d) = %q, expected %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestModel_FileBrowser_PressX_OnNonJson(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.selectedOption = 0
	
	// Create a dummy file with non-json ext
	m.entries = []FileEntry{
		{Name: "data.txt", IsDir: false, Size: 100},
	}
	m.fileCursor = 0
	
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if mResult.state != stateFileBrowser {
		t.Errorf("expected state to remain stateFileBrowser, got %v", mResult.state)
	}
	if mResult.scanPath != "" {
		t.Error("expected scanPath to be empty")
	}
}

func TestModel_FileBrowser_PressX_OnJson(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.selectedOption = 0
	m.currentDir = "/test/dir"
	
	m.entries = []FileEntry{
		{Name: "data.json", IsDir: false, Size: 100},
	}
	m.fileCursor = 0
	
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if mResult.state != stateConfirmSelection {
		t.Errorf("expected state to switch to stateConfirmSelection, got %v", mResult.state)
	}
	expectedPath := filepath.Join("/test/dir", "data.json")
	if mResult.scanPath != expectedPath {
		t.Errorf("expected scanPath to be %s, got %s", expectedPath, mResult.scanPath)
	}
}

func TestModel_ConfirmSelection_Cancel(t *testing.T) {
	m := NewModel()
	m.state = stateConfirmSelection
	m.scanPath = "/test/dir/data.json"
	
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if mResult.state != stateFileBrowser {
		t.Errorf("expected state to return to stateFileBrowser, got %v", mResult.state)
	}
	if mResult.scanPath != "" {
		t.Error("expected scanPath to be cleared")
	}
}

func TestModel_ConfirmSelection_Confirm(t *testing.T) {
	m := NewModel()
	m.state = stateConfirmSelection
	m.scanPath = "/test/dir/data.json"
	
	updatedModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if !mResult.confirmedScan {
		t.Error("expected confirmedScan to be true")
	}
	if cmd == nil {
		t.Error("expected non-nil quit command")
	}
}

func TestModel_FileBrowser_PressX_OnDirInFolderMode(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.selectedOption = 1 // Folder detection
	m.currentDir = "/test/dir"
	
	m.entries = []FileEntry{
		{Name: "subfolder", IsDir: true},
	}
	m.fileCursor = 0
	
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if mResult.state != stateConfirmSelection {
		t.Errorf("expected state to switch to stateConfirmSelection, got %v", mResult.state)
	}
	expectedPath := filepath.Join("/test/dir", "subfolder")
	if mResult.scanPath != expectedPath {
		t.Errorf("expected scanPath to be %s, got %s", expectedPath, mResult.scanPath)
	}
}

func TestModel_FileBrowser_PressX_OnParentDirIgnored(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.selectedOption = 1 // Folder detection
	m.currentDir = "/test/dir"
	
	m.entries = []FileEntry{
		{Name: "..", IsDir: true},
	}
	m.fileCursor = 0
	
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if mResult.state != stateFileBrowser {
		t.Errorf("expected state to remain stateFileBrowser, got %v", mResult.state)
	}
	if mResult.scanPath != "" {
		t.Error("expected scanPath to be empty")
	}
}
