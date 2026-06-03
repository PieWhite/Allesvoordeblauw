package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"goversion/models"
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
	if mResult.state != stateScanning {
		t.Errorf("expected state to switch to stateScanning, got %v", mResult.state)
	}
	if cmd == nil {
		t.Error("expected non-nil command")
	}
	if mResult.sharedBytesRead == nil || mResult.finishedChan == nil {
		t.Error("expected atomic pointer and channels to be initialized")
	}
}

func TestModel_ScanningState_MsgHandlers(t *testing.T) {
	m := NewModel()
	m.state = stateScanning
	var sharedBytes int64 = 150
	m.sharedBytesRead = &sharedBytes
	m.finishedChan = make(chan scanFinishedMsg, 1)
	m.scanTotalBytes = 1000
	m.scanReadBytes = 0

	// Handle tickMsg
	updatedModel, cmd := m.Update(tickMsg(time.Now()))
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	if mResult.scanReadBytes != 150 {
		t.Errorf("expected scanReadBytes to load 150 from atomic, got %d", mResult.scanReadBytes)
	}
	if cmd == nil {
		t.Error("expected tick command to be rescheduled")
	}

	// Handle scanFinishedMsg completion
	finishMsg := scanFinishedMsg{
		results:      []models.MLResult{{IP: "1.2.3.4", Probability: 0.99}},
		totalRecords: 1,
		duration:     time.Millisecond * 10,
		err:          nil,
	}
	updatedModel2, cmd2 := mResult.Update(finishMsg)
	mResult2, ok := updatedModel2.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	if mResult2.state != stateResults {
		t.Errorf("expected state to switch to stateResults, got %v", mResult2.state)
	}
	if len(mResult2.scanResults) != 1 || mResult2.scanResults[0].IP != "1.2.3.4" {
		t.Error("expected scanResults to be populated")
	}
	if mResult2.totalRecords != 1 {
		t.Errorf("expected totalRecords to be 1, got %d", mResult2.totalRecords)
	}
	if cmd2 != nil {
		t.Error("expected nil command after finishing scan")
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

func TestModel_ResultsState_PressX_TransitionsToFullLog(t *testing.T) {
	m := NewModel()
	m.state = stateResults
	m.scanPath = "/test/dir/data.json"
	m.confirmedScan = true
	m.scanError = nil // Simulate successful scan
	
	updatedModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	
	if mResult.state != stateFullLog {
		t.Errorf("expected state to switch to stateFullLog, got %v", mResult.state)
	}
	if mResult.fullLogText == "" {
		t.Error("expected fullLogText to be populated")
	}
	if cmd != nil {
		t.Error("expected cmd to be nil since we transition states")
	}
}

func TestModel_FullLog_Scrolling(t *testing.T) {
	m := NewModel()
	m.state = stateFullLog
	m.fullLogText = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10\nline 11\nline 12\nline 13\nline 14\nline 15\nline 16\nline 17\nline 18\nline 19\nline 20\nline 21\nline 22"
	m.logScrollRow = 0
	
	// Scroll down
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	if mResult.logScrollRow != 1 {
		t.Errorf("expected logScrollRow to be 1 after Down key, got %d", mResult.logScrollRow)
	}

	// Scroll down faster with Spacebar
	updatedModel2, _ := mResult.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	mResult2, ok := updatedModel2.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	if mResult2.logScrollRow != 4 { // maxScroll is len(lines) - 18 = 22 - 18 = 4. Clamps at 4.
		t.Errorf("expected logScrollRow to clamp at maxScroll 4, got %d", mResult2.logScrollRow)
	}

	// Scroll up
	updatedModel3, _ := mResult2.Update(tea.KeyMsg{Type: tea.KeyUp})
	mResult3, ok := updatedModel3.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	if mResult3.logScrollRow != 3 {
		t.Errorf("expected logScrollRow to be 3 after Up key, got %d", mResult3.logScrollRow)
	}

	// Esc returns to stateResults
	updatedModel4, _ := mResult3.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mResult4, ok := updatedModel4.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}
	if mResult4.state != stateResults {
		t.Errorf("expected state to return to stateResults, got %v", mResult4.state)
	}
}

func TestModel_WindowSizeMsg(t *testing.T) {
	m := NewModel()
	m.state = stateMenu

	// Handle window size msg
	updatedModel, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 40})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected model to be of type Model")
	}

	if mResult.width != 80 || mResult.height != 40 {
		t.Errorf("expected dimensions to be 80x40, got %dx%d", mResult.width, mResult.height)
	}

	if cmd != nil {
		t.Errorf("expected nil command, got %v", cmd)
	}
}

func TestModel_FileBrowser_Pagination(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.height = 20
	m.width = 60

	// Populate entries
	for i := 0; i < 15; i++ {
		name := "file_"
		if i == 0 {
			name += "0"
		} else if i == 10 {
			name += "10"
		} else {
			name += "other"
		}
		m.entries = append(m.entries, FileEntry{
			Name:  name + ".json",
			IsDir: false,
			Size:  100,
		})
	}
	m.fileCursor = 0

	view := m.View()
	if !strings.Contains(view, "file_0.json") {
		t.Error("expected first file to be in view initially")
	}
	if strings.Contains(view, "file_10.json") {
		t.Error("expected file_10.json to be out of view on page 1")
	}
	if !strings.Contains(view, "Page 1/2 (Items 1-10 of 15)") {
		t.Errorf("expected page indicator to be Page 1/2 (Items 1-10 of 15), view: %s", view)
	}

	// Move cursor deep down to 10
	m.fileCursor = 10
	viewAfterMove := m.View()
	if !strings.Contains(viewAfterMove, "file_10.json") {
		t.Error("expected file_10.json to be visible on page 2")
	}
	if strings.Contains(viewAfterMove, "file_0.json") {
		t.Error("expected file_0.json to be out of view on page 2")
	}
	if !strings.Contains(viewAfterMove, "Page 2/2 (Items 11-15 of 15)") {
		t.Errorf("expected page indicator to adjust to Page 2/2 (Items 11-15 of 15), view: %s", viewAfterMove)
	}
}

func TestModel_FileBrowser_PaginationKeys(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	
	// Create 25 dummy entries
	for i := 0; i < 25; i++ {
		m.entries = append(m.entries, FileEntry{
			Name:  "file.json",
			IsDir: false,
			Size:  100,
		})
	}
	m.fileCursor = 0

	// Test Right arrow / page down (should go from 0 to 10)
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	mResult, ok := updatedModel.(Model)
	if !ok {
		t.Fatalf("expected Model")
	}
	if mResult.fileCursor != 10 {
		t.Errorf("expected cursor to be 10, got %d", mResult.fileCursor)
	}

	// Test vim 'l' to go to next page (should go from 10 to 20)
	updatedModel2, _ := mResult.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("l")})
	mResult2, ok := updatedModel2.(Model)
	if !ok {
		t.Fatalf("expected Model")
	}
	if mResult2.fileCursor != 20 {
		t.Errorf("expected cursor to be 20, got %d", mResult2.fileCursor)
	}

	// Test Left arrow / page up (should go from 20 to 10)
	updatedModel3, _ := mResult2.Update(tea.KeyMsg{Type: tea.KeyLeft})
	mResult3, ok := updatedModel3.(Model)
	if !ok {
		t.Fatalf("expected Model")
	}
	if mResult3.fileCursor != 10 {
		t.Errorf("expected cursor to be 10, got %d", mResult3.fileCursor)
	}

	// Test vim 'h' to go to prev page (should go from 10 to 0)
	updatedModel4, _ := mResult3.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("h")})
	mResult4, ok := updatedModel4.(Model)
	if !ok {
		t.Fatalf("expected Model")
	}
	if mResult4.fileCursor != 0 {
		t.Errorf("expected cursor to be 0, got %d", mResult4.fileCursor)
	}
}

func TestModel_FileBrowser_PressX_OnCSV(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.selectedOption = 0
	m.currentDir = "/test/dir"
	
	m.entries = []FileEntry{
		{Name: "data.csv", IsDir: false, Size: 100},
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
	expectedPath := filepath.Join("/test/dir", "data.csv")
	if mResult.scanPath != expectedPath {
		t.Errorf("expected scanPath to be %s, got %s", expectedPath, mResult.scanPath)
	}
}
