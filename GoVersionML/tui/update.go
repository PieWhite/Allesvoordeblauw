/*
Package tui implements a Bubble Tea-based Terminal User Interface (TUI)
for Pencilgon, an XGBoost-based tool for botnet detection.

This file handles keyboard, tick, window resize, and scan transition logic.
*/
package tui

import (
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"goversion/config"
	"goversion/engine"
	"goversion/models"
	"goversion/pipeline"
	"goversion/reporter"
	"goversion/scanner"
	"goversion/utils"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m.handleTick(msg)

	case scanFinishedMsg:
		return m.handleScanFinished(msg)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleTick(msg tickMsg) (tea.Model, tea.Cmd) {
	if m.state == stateScanning {
		if m.sharedBytesRead != nil {
			m.scanReadBytes = atomic.LoadInt64(m.sharedBytesRead)
		}
		if m.sharedRecordsDecoded != nil {
			m.scanRecordsDecoded = atomic.LoadInt64(m.sharedRecordsDecoded)
		}
		if m.sharedRecordsAggregated != nil {
			m.scanRecordsAggregated = atomic.LoadInt64(m.sharedRecordsAggregated)
		}
		if m.sharedWindowsInferred != nil {
			m.scanWindowsInferred = atomic.LoadInt64(m.sharedWindowsInferred)
		}
		return m, tick()
	}
	return m, nil
}

func (m Model) handleScanFinished(msg scanFinishedMsg) (tea.Model, tea.Cmd) {
	m.scanDuration = msg.duration
	if msg.err != nil {
		m.scanError = msg.err
	} else {
		var realResults []models.MLResult
		for _, res := range msg.results {
			if res.IP != "" {
				realResults = append(realResults, res)
			}
		}
		sort.SliceStable(realResults, func(i, j int) bool {
			return realResults[i].Probability > realResults[j].Probability
		})
		m.scanResults = realResults
		m.totalCommunicatingIPs = msg.totalCommunicatingIPs
		m.totalRecords = msg.totalRecords
	}
	m.state = stateResults
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "esc":
		return m.handleEscape()
	}

	switch m.state {
	case stateMenu:
		return m.handleMenuKey(msg)
	case stateConfiguration:
		return m.handleConfigurationKey(msg)
	case stateFileBrowser:
		return m.handleFileBrowserKey(msg)
	case stateConfirmSelection:
		return m.handleConfirmSelectionKey(msg)
	case stateResults:
		return m.handleResultsKey(msg)
	case stateFullLog:
		return m.handleFullLogKey(msg)
	}

	return m, nil
}

func (m Model) handleEscape() (tea.Model, tea.Cmd) {
	if m.state == stateScanning {
		return m, nil
	}
	if m.state == stateFullLog {
		m.state = stateResults
		m.logScrollRow = 0
		return m, nil
	}
	if m.state == stateResults {
		m.state = stateFileBrowser
		m.scanPath = ""
		m.scanJSONCount = 0
		m.scanNDJSONCount = 0
		m.scanPCAPCount = 0
		m.scanCSVCount = 0
		m.scanResults = nil
		m.totalRecords = 0
		m.scanError = nil
		return m, nil
	}
	if m.state == stateConfirmSelection {
		m.state = stateFileBrowser
		m.scanPath = ""
		m.scanJSONCount = 0
		m.scanNDJSONCount = 0
		m.scanPCAPCount = 0
		m.scanCSVCount = 0
		return m, nil
	}
	if m.state == stateFileBrowser {
		m.state = stateMenu
		return m, nil
	}
	if m.state == stateConfiguration {
		m.state = stateMenu
		m.cursor = 0
		return m, nil
	}
	m.quitting = true
	return m, tea.Quit
}

func (m Model) handleMenuKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		} else {
			m.cursor = 2
		}
	case "down", "j":
		if m.cursor < 2 {
			m.cursor++
		} else {
			m.cursor = 0
		}
	case "enter", " ":
		if m.cursor == 2 {
			m.state = stateConfiguration
			plan := utils.GetConcurrencyPlan()
			m.cfgConcurrentFiles = plan.ConcurrentFiles
			m.cfgWorkersPerFile = plan.WorkersPerFile
			m.cfgSubnet = m.savedSubnet
			m.cfgCursor = 0
		} else {
			m.selectedOption = m.cursor
			if err := m.loadDirectory("."); err == nil {
				m.state = stateFileBrowser
			}
		}
	}
	return m, nil
}

func (m Model) handleConfigurationKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cfgCursor > 0 {
			m.cfgCursor--
		} else {
			m.cfgCursor = 5
		}
	case "down", "j":
		if m.cfgCursor < 5 {
			m.cfgCursor++
		} else {
			m.cfgCursor = 0
		}
	case "left", "h", "-":
		if m.cfgCursor == 0 {
			if m.cfgConcurrentFiles > 1 {
				m.cfgConcurrentFiles--
			}
		} else if m.cfgCursor == 1 {
			if m.cfgWorkersPerFile > 1 {
				m.cfgWorkersPerFile--
			}
		}
	case "right", "l", "+":
		if m.cfgCursor == 0 {
			if m.cfgConcurrentFiles < 64 {
				m.cfgConcurrentFiles++
			}
		} else if m.cfgCursor == 1 {
			if m.cfgWorkersPerFile < 64 {
				m.cfgWorkersPerFile++
			}
		}
	case "backspace":
		if m.cfgCursor == 2 {
			if len(m.cfgSubnet) > 0 {
				m.cfgSubnet = m.cfgSubnet[:len(m.cfgSubnet)-1]
			}
		}
	case "enter", " ":
		switch m.cfgCursor {
		case 2:
		case 3:
			utils.ConfiguredConcurrentFiles = m.cfgConcurrentFiles
			utils.ConfiguredWorkersPerFile = m.cfgWorkersPerFile
			m.savedSubnet = m.cfgSubnet
			m.state = stateMenu
			m.cursor = 0
		case 4:
			utils.ConfiguredConcurrentFiles = 0
			utils.ConfiguredWorkersPerFile = 0
			m.savedSubnet = ""
			m.cfgSubnet = ""
			m.state = stateMenu
			m.cursor = 0
		case 5:
			m.state = stateMenu
			m.cursor = 0
		}
	case "esc":
		m.state = stateMenu
		m.cursor = 0
	default:
		if m.cfgCursor == 2 {
			key := msg.String()
			if len(key) == 1 {
				c := key[0]
				if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '/' || c == '*' || c == ':' || c == '-' {
					m.cfgSubnet += key
				}
			}
		}
	}
	return m, nil
}

func (m Model) handleFileBrowserKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.fileCursor > 0 {
			m.fileCursor--
		} else if len(m.entries) > 0 {
			m.fileCursor = len(m.entries) - 1
		}
	case "down", "j":
		if m.fileCursor < len(m.entries)-1 {
			m.fileCursor++
		} else {
			m.fileCursor = 0
		}
	case "left", "h", "pgup":
		if len(m.entries) > 0 {
			m.fileCursor -= 10
			if m.fileCursor < 0 {
				m.fileCursor = 0
			}
		}
	case "right", "l", "pgdown":
		if len(m.entries) > 0 {
			m.fileCursor += 10
			if m.fileCursor >= len(m.entries) {
				m.fileCursor = len(m.entries) - 1
			}
		}
	case "backspace":
		parent := filepath.Dir(m.currentDir)
		if parent != m.currentDir {
			_ = m.loadDirectory(parent)
		}
	case "x", "X":
		if len(m.entries) > 0 && m.fileCursor < len(m.entries) {
			entry := m.entries[m.fileCursor]
			if m.selectedOption == 0 {
				if !entry.IsDir {
					ext := strings.ToLower(filepath.Ext(entry.Name))
					if ext == ".json" || ext == ".ndjson" || ext == ".pcap" || ext == ".csv" {
						m.scanPath = filepath.Join(m.currentDir, entry.Name)
						m.scanJSONCount, m.scanNDJSONCount, m.scanPCAPCount, m.scanCSVCount = m.getScanFileCounts()
						m.state = stateConfirmSelection
					}
				}
			} else if m.selectedOption == 1 {
				if entry.IsDir && entry.Name != ".." {
					m.scanPath = filepath.Join(m.currentDir, entry.Name)
					m.scanJSONCount, m.scanNDJSONCount, m.scanPCAPCount, m.scanCSVCount = m.getScanFileCounts()
					m.state = stateConfirmSelection
				}
			}
		}
	case "enter":
		if len(m.entries) > 0 && m.fileCursor < len(m.entries) {
			entry := m.entries[m.fileCursor]
			if entry.IsDir {
				var targetPath string
				if entry.Name == ".." {
					targetPath = filepath.Dir(m.currentDir)
				} else {
					targetPath = filepath.Join(m.currentDir, entry.Name)
				}
				_ = m.loadDirectory(targetPath)
			}
		}
	}
	return m, nil
}

func (m Model) handleConfirmSelectionKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.confirmedScan = true
		m.state = stateScanning
		m.scanTotalBytes = m.getScanTotalSize()
		m.scanReadBytes = 0
		m.finishedChan = make(chan scanFinishedMsg, 1)

		var initialBytes int64
		m.sharedBytesRead = &initialBytes
		var initialDecoded int64
		m.sharedRecordsDecoded = &initialDecoded
		var initialAggregated int64
		m.sharedRecordsAggregated = &initialAggregated
		var initialInferred int64
		m.sharedWindowsInferred = &initialInferred

		go func(scanPath string, subnet string, finishedChan chan scanFinishedMsg, sharedBytesRead, sharedRecordsDecoded, sharedRecordsAggregated, sharedWindowsInferred *int64) {
			old := pipeline.OnProgress
			pipeline.OnProgress = func(delta int64) {
				atomic.AddInt64(sharedBytesRead, delta)
			}
			oldEvent := pipeline.OnProgressEvent
			pipeline.OnProgressEvent = func(event pipeline.ProgressEvent) {
				switch event.Stage {
				case pipeline.ProgressBytesRead:
				case pipeline.ProgressRecordsDecoded:
					atomic.AddInt64(sharedRecordsDecoded, event.Delta)
				case pipeline.ProgressRecordsAggregated:
					atomic.AddInt64(sharedRecordsAggregated, event.Delta)
				case pipeline.ProgressWindowsInferred:
					atomic.AddInt64(sharedWindowsInferred, event.Delta)
				}
			}

			scanner.OnRecordsDecoded = func(delta int64) {
				if pipeline.OnProgressEvent != nil {
					pipeline.OnProgressEvent(pipeline.ProgressEvent{
						Stage: pipeline.ProgressRecordsDecoded,
						Delta: delta,
					})
				}
			}
			engine.OnRecordsAggregated = func(delta int64) {
				if pipeline.OnProgressEvent != nil {
					pipeline.OnProgressEvent(pipeline.ProgressEvent{
						Stage: pipeline.ProgressRecordsAggregated,
						Delta: delta,
					})
				}
			}
			engine.OnWindowsInferred = func(delta int64) {
				if pipeline.OnProgressEvent != nil {
					pipeline.OnProgressEvent(pipeline.ProgressEvent{
						Stage: pipeline.ProgressWindowsInferred,
						Delta: delta,
					})
				}
			}

			defer func() {
				pipeline.OnProgress = old
				pipeline.OnProgressEvent = oldEvent
				scanner.OnRecordsDecoded = nil
				engine.OnRecordsAggregated = nil
				engine.OnWindowsInferred = nil
			}()

			oldSilence := pipeline.Silence
			pipeline.Silence = true
			defer func() {
				pipeline.Silence = oldSilence
			}()

			start := time.Now()
			appConfig := &config.AppConfig{
				InputPath:   scanPath,
				SkipConfirm: true,
				Subnet:      subnet,
			}
			results, totalUnique, totalRecords, err := pipeline.RunPipelineForInput(appConfig)
			duration := time.Since(start)

			finishedChan <- scanFinishedMsg{
				results:               results,
				totalCommunicatingIPs: totalUnique,
				totalRecords:          totalRecords,
				duration:              duration,
				err:                   err,
			}
		}(m.scanPath, m.savedSubnet, m.finishedChan, m.sharedBytesRead, m.sharedRecordsDecoded, m.sharedRecordsAggregated, m.sharedWindowsInferred)

		return m, tea.Batch(
			listenForFinished(m.finishedChan),
			tick(),
		)

	case "n", "N":
		m.state = stateFileBrowser
		m.scanPath = ""
		m.scanJSONCount = 0
		m.scanNDJSONCount = 0
		m.scanPCAPCount = 0
		m.scanCSVCount = 0
	}
	return m, nil
}

func (m Model) handleResultsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "x" || msg.String() == "X" {
		if m.scanError == nil {
			var logBuilder strings.Builder
			reporter.PrintSummary(&logBuilder, m.scanResults, m.totalCommunicatingIPs, m.totalRecords, m.scanDuration)
			m.fullLogText = logBuilder.String()
			m.logScrollRow = 0
			m.state = stateFullLog
		}
	}
	return m, nil
}

func (m Model) handleFullLogKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	lines := strings.Split(m.fullLogText, "\n")
	maxLinesToShow := 18
	if m.height > 0 {
		maxLinesToShow = m.height - 10
		if maxLinesToShow < 5 {
			maxLinesToShow = 5
		}
	}
	maxScroll := len(lines) - maxLinesToShow
	if maxScroll < 0 {
		maxScroll = 0
	}

	switch msg.String() {
	case "up", "k":
		if m.logScrollRow > 0 {
			m.logScrollRow--
		}
	case "down", "j":
		if m.logScrollRow < maxScroll {
			m.logScrollRow++
		}
	case "pgup", "ctrl+u":
		m.logScrollRow -= 10
		if m.logScrollRow < 0 {
			m.logScrollRow = 0
		}
	case "pgdown", "ctrl+d", " ":
		m.logScrollRow += 10
		if m.logScrollRow > maxScroll {
			m.logScrollRow = maxScroll
		}
	}
	return m, nil
}
