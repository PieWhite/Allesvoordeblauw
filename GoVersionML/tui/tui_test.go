package tui

import (
	"errors"
	"io"
	"os"
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

func TestModel_FileBrowser_ViewportScrolling(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.height = 20 // This makes maxEntries = 20 - 15 = 5
	m.width = 60

	// Populate entries without fmt
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
		t.Error("expected file_10.json to be out of view viewport initially")
	}
	if !strings.Contains(view, "Showing 1-5 of 15") {
		t.Errorf("expected viewport range to be Showing 1-5 of 15, view: %s", view)
	}

	// Move cursor deep down
	m.fileCursor = 10
	viewAfterMove := m.View()
	if !strings.Contains(viewAfterMove, "file_10.json") {
		t.Error("expected file_10.json to be visible after moving cursor to 10")
	}
	if !strings.Contains(viewAfterMove, "Showing 9-13 of 15") { // Center window around 10: 10 - 5/2 = 8. start = 8, end = 13.
		t.Errorf("expected viewport range to adjust to Showing 9-13 of 15, view: %s", viewAfterMove)
	}
}

func TestGetScanTotalSizeAndCounts(t *testing.T) {
	tempDir := t.TempDir()

	// Write files
	writeTemp := func(name string, size int) string {
		p := filepath.Join(tempDir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("failed to mkdir: %v", err)
		}
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
		return p
	}

	f1 := writeTemp("a.json", 10)
	f2 := writeTemp("b.ndjson", 20)
	f3 := writeTemp("c.pcap", 30)
	writeTemp("d.txt", 40) // unsupported
	writeTemp("sub/e.json", 50)

	m := NewModel()

	// 1. Nonexistent path
	m.scanPath = filepath.Join(tempDir, "nonexistent.json")
	if sz := m.getScanTotalSize(); sz != 0 {
		t.Errorf("expected 0 for nonexistent, got %d", sz)
	}
	c1, c2, c3 := m.getScanFileCounts()
	if c1 != 0 || c2 != 0 || c3 != 0 {
		t.Errorf("expected 0 counts for nonexistent, got %d,%d,%d", c1, c2, c3)
	}

	// 2. Single file path
	m.scanPath = f1
	if sz := m.getScanTotalSize(); sz != 10 {
		t.Errorf("expected 10, got %d", sz)
	}
	c1, c2, c3 = m.getScanFileCounts()
	if c1 != 1 || c2 != 0 || c3 != 0 {
		t.Errorf("expected 1,0,0, got %d,%d,%d", c1, c2, c3)
	}

	m.scanPath = f2
	c1, c2, c3 = m.getScanFileCounts()
	if c1 != 0 || c2 != 1 || c3 != 0 {
		t.Errorf("expected 0,1,0, got %d,%d,%d", c1, c2, c3)
	}

	m.scanPath = f3
	c1, c2, c3 = m.getScanFileCounts()
	if c1 != 0 || c2 != 0 || c3 != 1 {
		t.Errorf("expected 0,0,1, got %d,%d,%d", c1, c2, c3)
	}

	// 3. Directory path
	m.scanPath = tempDir
	// Total size should sum: a.json (10) + b.ndjson (20) + c.pcap (30) + sub/e.json (50) = 110
	if sz := m.getScanTotalSize(); sz != 110 {
		t.Errorf("expected 110, got %d", sz)
	}
	c1, c2, c3 = m.getScanFileCounts()
	if c1 != 2 || c2 != 1 || c3 != 1 {
		t.Errorf("expected 2,1,1, got %d,%d,%d", c1, c2, c3)
	}

	// 4. Single file unsupported
	m.scanPath = filepath.Join(tempDir, "d.txt")
	c1, c2, c3 = m.getScanFileCounts()
	if c1 != 0 || c2 != 0 || c3 != 0 {
		t.Errorf("expected 0,0,0, got %d,%d,%d", c1, c2, c3)
	}
}

func TestModel_View_AllStates(t *testing.T) {
	t.Run("stateFileBrowser Empty and Full", func(t *testing.T) {
		m := NewModel()
		m.state = stateFileBrowser
		m.currentDir = "/test"
		m.entries = []FileEntry{}
		view := m.View()
		if !strings.Contains(view, "(Empty Directory)") {
			t.Error("expected Empty Directory indicator")
		}

		m.entries = []FileEntry{
			{Name: "..", IsDir: true},
			{Name: "sub", IsDir: true},
			{Name: "data.json", IsDir: false, Size: 1024},
			{Name: "data.ndjson", IsDir: false, Size: 2048},
			{Name: "data.pcap", IsDir: false, Size: 3072},
			{Name: "readme.txt", IsDir: false, Size: 50},
		}
		m.fileCursor = 2
		m.height = 10 // force viewport scroll rendering
		m.width = 40
		viewFull := m.View()
		if !strings.Contains(viewFull, "data.json") {
			t.Error("expected data.json in view")
		}
	})

	t.Run("stateConfirmSelection States", func(t *testing.T) {
		m := NewModel()
		m.state = stateConfirmSelection
		m.scanPath = "/test/file.json"
		m.selectedOption = 0
		viewSingle := m.View()
		if !strings.Contains(viewSingle, "Proceed with file.json?") {
			t.Error("expected single file confirmation prompt")
		}

		m.selectedOption = 1
		m.scanPath = "/test/myfolder"
		m.scanJSONCount = 5
		m.scanNDJSONCount = 10
		m.scanPCAPCount = 15
		viewFolder := m.View()
		if !strings.Contains(viewFolder, "Proceed with scanning folder myfolder?") {
			t.Error("expected folder confirmation prompt")
		}
		if !strings.Contains(viewFolder, "JSON files:   5") {
			t.Error("expected JSON files count in folder confirmation view")
		}
	})

	t.Run("stateScanning States", func(t *testing.T) {
		m := NewModel()
		m.state = stateScanning
		m.scanPath = "/test/file.json"
		m.selectedOption = 0
		m.scanTotalBytes = 1000
		m.scanReadBytes = 450
		view := m.View()
		if !strings.Contains(view, "Pencilgon Scan in Progress...") {
			t.Error("expected Scanning state view title")
		}
		if !strings.Contains(view, "45.0%") {
			t.Error("expected percentage calculation in scan progress view")
		}

		m.selectedOption = 1
		m.scanJSONCount = 2
		m.scanNDJSONCount = 3
		m.scanPCAPCount = 4
		viewFolder := m.View()
		if !strings.Contains(viewFolder, "Contains: 2 JSON, 3 NDJSON, 4 PCAP files") {
			t.Error("expected folder counts in scanning view")
		}
	})

	t.Run("stateResults States", func(t *testing.T) {
		m := NewModel()
		m.state = stateResults
		m.scanPath = "/test/file.json"

		// 1. With error
		m.scanError = errors.New("something went wrong")
		viewErr := m.View()
		if !strings.Contains(viewErr, "Scan Failed:") || !strings.Contains(viewErr, "something went wrong") {
			t.Error("expected failure message in results view")
		}

		// 2. Success, 0 results
		m.scanError = nil
		m.scanResults = []models.MLResult{}
		m.totalRecords = 0
		viewZero := m.View()
		if !strings.Contains(viewZero, "(No communicating IPs found)") {
			t.Error("expected no communicating IPs indicator")
		}

		// 3. Success, multiple results (botnet and benign)
		m.scanResults = []models.MLResult{
			{IP: "1.2.3.4", Probability: 99.9, IsBotnet: true},
			{IP: "5.6.7.8", Probability: 1.2, IsBotnet: false},
		}
		m.totalRecords = 100
		viewResults := m.View()
		if !strings.Contains(viewResults, "Processed Records: 100") {
			t.Error("expected total records display")
		}
		if !strings.Contains(viewResults, "IP: 1.2.3.4") || !strings.Contains(viewResults, "BOTNET") {
			t.Error("expected botnet IP log")
		}
		if !strings.Contains(viewResults, "IP: 5.6.7.8") || !strings.Contains(viewResults, "BENIGN") {
			t.Error("expected benign IP log")
		}
	})

	t.Run("stateFullLog States", func(t *testing.T) {
		m := NewModel()
		m.state = stateFullLog
		m.fullLogText = "row1\nrow2\nrow3\nrow4\nrow5\nrow6\nrow7\nrow8\nrow9\nrow10\nrow11\nrow12\nrow13\nrow14\nrow15\nrow16\nrow17\nrow18\nrow19\nrow20\nrow21\nrow22\nrow23\nrow24\nrow25"
		m.logScrollRow = 2
		m.height = 15 // forces scrollbar to render
		m.width = 50
		view := m.View()
		if !strings.Contains(view, "Pencilgon Full Scan Log") {
			t.Error("expected Full Scan Log view title")
		}
		if !strings.Contains(view, "row3") { // starting from scroll row 2 (0-indexed)
			t.Error("expected row3 in scrolled view")
		}
	})
}

func TestModel_Update_KeypressEscCases(t *testing.T) {
	tests := []struct {
		name          string
		state         sessionState
		expectedState sessionState
	}{
		{
			name:          "esc on stateScanning is ignored",
			state:         stateScanning,
			expectedState: stateScanning,
		},
		{
			name:          "esc on stateConfirmSelection goes to browser",
			state:         stateConfirmSelection,
			expectedState: stateFileBrowser,
		},
		{
			name:          "esc on stateResults goes to browser",
			state:         stateResults,
			expectedState: stateFileBrowser,
		},
		{
			name:          "esc on stateFullLog goes to results",
			state:         stateFullLog,
			expectedState: stateResults,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel()
			m.state = tt.state
			m.scanPath = "/some/path"
			m.scanResults = []models.MLResult{{IP: "1.1.1.1"}}
			m.totalRecords = 5

			updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
			mResult, ok := updatedModel.(Model)
			if !ok {
				t.Fatalf("expected updated model to be Model")
			}
			if mResult.state != tt.expectedState {
				t.Errorf("expected state %v, got %v", tt.expectedState, mResult.state)
			}
			if tt.state == stateResults && mResult.scanResults != nil {
				t.Error("expected scanResults to be cleared")
			}
			if tt.state == stateConfirmSelection && mResult.scanPath != "" {
				t.Error("expected scanPath to be cleared")
			}
		})
	}
}

func TestModel_Update_FileBrowserNavigationEdgeCases(t *testing.T) {
	m := NewModel()
	m.state = stateFileBrowser
	m.entries = []FileEntry{
		{Name: "..", IsDir: true},
		{Name: "a.json", IsDir: false},
		{Name: "b.json", IsDir: false},
	}

	// 1. Move up from index 0 should wrap around to index 2 (last)
	m.fileCursor = 0
	upModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	upResult := upModel.(Model)
	if upResult.fileCursor != 2 {
		t.Errorf("expected wrap-around up to 2, got %d", upResult.fileCursor)
	}

	// 2. Move down from index 2 should wrap around to index 0 (first)
	m.fileCursor = 2
	downModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	downResult := downModel.(Model)
	if downResult.fileCursor != 0 {
		t.Errorf("expected wrap-around down to 0, got %d", downResult.fileCursor)
	}

	// 3. Selection key 'x' on Directory while in Single File Mode (0) should be ignored
	m.selectedOption = 0
	m.fileCursor = 0 // ".." which is a directory
	xDirModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	xDirResult := xDirModel.(Model)
	if xDirResult.state != stateFileBrowser {
		t.Errorf("expected state to remain fileBrowser, got %v", xDirResult.state)
	}

	// 4. Selection key 'x' on File while in Folder Mode (1) should be ignored
	m.selectedOption = 1
	m.fileCursor = 1 // "a.json" which is a file
	xFileModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	xFileResult := xFileModel.(Model)
	if xFileResult.state != stateFileBrowser {
		t.Errorf("expected state to remain fileBrowser, got %v", xFileResult.state)
	}

	// 5. Selection key 'x' on ".." in Folder Mode should be ignored
	m.selectedOption = 1
	m.fileCursor = 0 // ".." which is a directory but parent directory indicator
	xParentModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	xParentResult := xParentModel.(Model)
	if xParentResult.state != stateFileBrowser {
		t.Errorf("expected state to remain fileBrowser, got %v", xParentResult.state)
	}
}

func TestModel_Update_FullLogScrollCommands(t *testing.T) {
	m := NewModel()
	m.state = stateFullLog
	m.fullLogText = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n21\n22\n23\n24\n25"
	m.height = 15 // maxLinesToShow = 15 - 10 = 5. maxScroll = 25 - 5 = 20.
	m.logScrollRow = 10

	// 1. pgup / ctrl+u should scroll up by 10 rows
	pgupModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("pgup")})
	if pgupModel.(Model).logScrollRow != 0 {
		t.Errorf("expected scroll row 0, got %d", pgupModel.(Model).logScrollRow)
	}

	m.logScrollRow = 10
	ctrlUModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	if ctrlUModel.(Model).logScrollRow != 0 {
		t.Errorf("expected scroll row 0, got %d", ctrlUModel.(Model).logScrollRow)
	}

	// 2. pgdown / ctrl+d should scroll down by 10 rows
	m.logScrollRow = 5
	pgdownModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("pgdown")})
	if pgdownModel.(Model).logScrollRow != 15 {
		t.Errorf("expected scroll row 15, got %d", pgdownModel.(Model).logScrollRow)
	}

	m.logScrollRow = 5
	ctrlDModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	if ctrlDModel.(Model).logScrollRow != 15 {
		t.Errorf("expected scroll row 15, got %d", ctrlDModel.(Model).logScrollRow)
	}
}

func TestStart(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ProgramOptions = []tea.ProgramOption{
		tea.WithInput(r),
		tea.WithOutput(io.Discard),
	}
	t.Cleanup(func() {
		ProgramOptions = nil
	})

	go func() {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("q"))
	}()

	path, err := Start()
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path from cancelled Start run, got %q", path)
	}
}

