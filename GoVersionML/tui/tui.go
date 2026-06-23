/*
Package tui implements a Bubble Tea-based Terminal User Interface (TUI)
for Pencilgon, an XGBoost-based tool for botnet detection.

This file defines the TUI state, the Model structure, state initialization,
and directory loading utilities.
*/
package tui

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"goversion/models"

	tea "github.com/charmbracelet/bubbletea"
)

type sessionState int

const (
	stateMenu sessionState = iota
	stateFileBrowser
	stateConfirmSelection
	stateScanning
	stateResults
	stateFullLog
	stateConfiguration
)

type FileEntry struct {
	Name  string
	IsDir bool
	Size  int64
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(time.Millisecond*50, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func listenForFinished(finishedChan chan scanFinishedMsg) tea.Cmd {
	return func() tea.Msg {
		return <-finishedChan
	}
}

type scanFinishedMsg struct {
	results               []models.MLResult
	totalCommunicatingIPs int
	totalRecords          int64
	duration              time.Duration
	err                   error
}

type Model struct {
	state          sessionState
	cursor         int
	quitting       bool
	selectedOption int

	currentDir string
	entries    []FileEntry
	fileCursor int

	scanPath        string
	confirmedScan   bool
	scanJSONCount   int
	scanNDJSONCount int
	scanPCAPCount   int
	scanCSVCount    int

	sharedBytesRead         *int64
	sharedRecordsDecoded    *int64
	sharedRecordsAggregated *int64
	sharedWindowsInferred   *int64
	finishedChan            chan scanFinishedMsg
	scanTotalBytes          int64
	scanReadBytes           int64
	scanRecordsDecoded      int64
	scanRecordsAggregated   int64
	scanWindowsInferred     int64

	scanResults           []models.MLResult
	totalCommunicatingIPs int
	totalRecords          int64
	scanError             error
	scanDuration          time.Duration

	fullLogText  string
	logScrollRow int

	width  int
	height int

	cfgConcurrentFiles int
	cfgWorkersPerFile  int
	cfgSubnet          string
	savedSubnet        string
	cfgCursor          int
}

func NewModel() Model {
	return Model{
		state:       stateMenu,
		cursor:      0,
		cfgSubnet:   "",
		savedSubnet: "",
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m *Model) loadDirectory(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	m.currentDir = abs

	entries, err := os.ReadDir(abs)
	if err != nil {
		return err
	}

	m.entries = nil

	parent := filepath.Dir(abs)
	if parent != abs {
		m.entries = append(m.entries, FileEntry{
			Name:  "..",
			IsDir: true,
		})
	}

	for _, entry := range entries {
		info, err := entry.Info()
		var size int64
		if err == nil {
			size = info.Size()
		}
		m.entries = append(m.entries, FileEntry{
			Name:  entry.Name(),
			IsDir: entry.IsDir(),
			Size:  size,
		})
	}
	m.fileCursor = 0
	return nil
}

func (m *Model) getScanTotalSize() int64 {
	info, err := os.Stat(m.scanPath)
	if err != nil {
		return 0
	}
	if !info.IsDir() {
		return info.Size()
	}

	var total int64
	_ = filepath.WalkDir(m.scanPath, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".json" || ext == ".ndjson" || ext == ".pcap" || ext == ".csv" {
				if fInfo, fErr := d.Info(); fErr == nil {
					total += fInfo.Size()
				}
			}
		}
		return nil
	})
	return total
}

func (m *Model) getScanFileCounts() (jsonCount, ndjsonCount, pcapCount, csvCount int) {
	info, err := os.Stat(m.scanPath)
	if err != nil {
		return 0, 0, 0, 0
	}
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(m.scanPath))
		switch ext {
		case ".json":
			return 1, 0, 0, 0
		case ".ndjson":
			return 0, 1, 0, 0
		case ".pcap":
			return 0, 0, 1, 0
		case ".csv":
			return 0, 0, 0, 1
		}
		return 0, 0, 0, 0
	}

	_ = filepath.WalkDir(m.scanPath, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".json":
				jsonCount++
			case ".ndjson":
				ndjsonCount++
			case ".pcap":
				pcapCount++
			case ".csv":
				csvCount++
			}
		}
		return nil
	})
	return
}

func Start() (string, error) {
	originalLogOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(originalLogOutput)

	m := NewModel()
	p := tea.NewProgram(m, ProgramOptions...)
	finalModel, err := p.Run()
	if err != nil {
		return "", err
	}

	if tuiModel, ok := finalModel.(Model); ok {
		if tuiModel.confirmedScan {
			return tuiModel.scanPath, nil
		}
	}
	return "", nil
}
