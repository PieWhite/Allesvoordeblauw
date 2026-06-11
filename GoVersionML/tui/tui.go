package tui

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"goversion/config"
	"goversion/models"
	"goversion/pipeline"
	"goversion/reporter"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type sessionState int

const (
	stateMenu sessionState = iota
	stateFileBrowser
	stateConfirmSelection
	stateScanning
	stateResults
	stateFullLog
)

// FileEntry represents a file or directory item.
type FileEntry struct {
	Name  string
	IsDir bool
	Size  int64
}

// Custom Bubble Tea message definitions for concurrent progression
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
	results      []models.MLResult
	totalRecords int64
	duration     time.Duration
	err          error
}

// Model defines the state of our TUI.
type Model struct {
	state          sessionState
	cursor         int
	quitting       bool
	selectedOption int // 0 = Single file detection, 1 = Folder detection

	// Directory view fields
	currentDir string
	entries    []FileEntry
	fileCursor int

	// Scan selection fields
	scanPath        string
	confirmedScan   bool
	scanJSONCount   int
	scanNDJSONCount int
	scanPCAPCount   int

	// Background scanning channels
	sharedBytesRead *int64
	finishedChan    chan scanFinishedMsg
	scanTotalBytes  int64
	scanReadBytes   int64

	// Scan results fields
	scanResults  []models.MLResult
	totalRecords int64
	scanError    error
	scanDuration time.Duration

	// Full Log scroll fields
	fullLogText  string
	logScrollRow int

	// Terminal window dimensions
	width  int
	height int
}

// NewModel initializes the TUI model.
func NewModel() Model {
	return Model{
		state:  stateMenu,
		cursor: 0,
	}
}

// Init initializes the Bubble Tea loop.
func (m Model) Init() tea.Cmd {
	return nil
}

// loadDirectory reads files and subdirectories of the target folder.
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

	// Always add parent directory option ".." unless we are at root level
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

// getScanTotalSize calculates the total size of files to scan (supports single file or folders).
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
			if ext == ".json" || ext == ".ndjson" || ext == ".pcap" {
				if fInfo, fErr := d.Info(); fErr == nil {
					total += fInfo.Size()
				}
			}
		}
		return nil
	})
	return total
}

// getScanFileCounts walks the target path and counts JSON, NDJSON, and PCAP files.
func (m *Model) getScanFileCounts() (jsonCount, ndjsonCount, pcapCount int) {
	info, err := os.Stat(m.scanPath)
	if err != nil {
		return 0, 0, 0
	}
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(m.scanPath))
		switch ext {
		case ".json":
			return 1, 0, 0
		case ".ndjson":
			return 0, 1, 0
		case ".pcap":
			return 0, 0, 1
		}
		return 0, 0, 0
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
			}
		}
		return nil
	})
	return
}

// Update handles message updates in the Bubble Tea loop.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	// Custom thread-safe concurrent message routing
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		if m.state == stateScanning {
			if m.sharedBytesRead != nil {
				m.scanReadBytes = atomic.LoadInt64(m.sharedBytesRead)
			}
			return m, tick()
		}
		return m, nil

	case scanFinishedMsg:
		m.scanDuration = msg.duration
		if msg.err != nil {
			m.scanError = msg.err
		} else {
			// Sort results descending by ML probability
			sort.SliceStable(msg.results, func(i, j int) bool {
				return msg.results[i].Probability > msg.results[j].Probability
			})
			m.scanResults = msg.results
			m.totalRecords = msg.totalRecords
		}
		m.state = stateResults
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "esc":
			if m.state == stateScanning {
				// Prevent escaping while active scans run to preserve safety
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
				return m, nil
			}
			if m.state == stateFileBrowser {
				m.state = stateMenu
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		}

		if m.state == stateMenu {
			switch msg.String() {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				} else {
					m.cursor = 1
				}
			case "down", "j":
				if m.cursor < 1 {
					m.cursor++
				} else {
					m.cursor = 0
				}
			case "enter", " ":
				m.selectedOption = m.cursor
				if err := m.loadDirectory("."); err == nil {
					m.state = stateFileBrowser
				}
			}
		} else if m.state == stateFileBrowser {
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
							if ext == ".json" || ext == ".ndjson" || ext == ".pcap" {
								m.scanPath = filepath.Join(m.currentDir, entry.Name)
								m.scanJSONCount, m.scanNDJSONCount, m.scanPCAPCount = m.getScanFileCounts()
								m.state = stateConfirmSelection
							}
						}
					} else if m.selectedOption == 1 {
						if entry.IsDir && entry.Name != ".." {
							m.scanPath = filepath.Join(m.currentDir, entry.Name)
							m.scanJSONCount, m.scanNDJSONCount, m.scanPCAPCount = m.getScanFileCounts()
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
		} else if m.state == stateConfirmSelection {
			switch msg.String() {
			case "y", "Y":
				m.confirmedScan = true
				m.state = stateScanning
				m.scanTotalBytes = m.getScanTotalSize()
				m.scanReadBytes = 0
				m.finishedChan = make(chan scanFinishedMsg, 1)

				var initialBytes int64
				m.sharedBytesRead = &initialBytes

				// Fire background scanning thread asynchronously
				go func(scanPath string, finishedChan chan scanFinishedMsg, sharedBytesRead *int64) {
					old := pipeline.OnProgress
					pipeline.OnProgress = func(delta int64) {
						atomic.AddInt64(sharedBytesRead, delta)
					}
					defer func() {
						pipeline.OnProgress = old
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
					}
					results, totalRecords, err := pipeline.RunPipelineForInput(appConfig)
					duration := time.Since(start)

					finishedChan <- scanFinishedMsg{
						results:      results,
						totalRecords: totalRecords,
						duration:     duration,
						err:          err,
					}
				}(m.scanPath, m.finishedChan, m.sharedBytesRead)

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
			}
		} else if m.state == stateResults {
			switch msg.String() {
			case "x", "X":
				if m.scanError == nil {
					// Format scan report using reporter logic to string builder
					var logBuilder strings.Builder
					reporter.PrintSummary(&logBuilder, m.scanResults, m.totalRecords, m.scanDuration)
					m.fullLogText = logBuilder.String()
					m.logScrollRow = 0
					m.state = stateFullLog
				}
			}
		} else if m.state == stateFullLog {
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
		}
	}
	return m, nil
}

// View renders the terminal user interface.
func (m Model) View() string {
	if m.quitting {
		return "\n  Goodbye from Pencilgon!\n\n"
	}

	banner := `
 ███████████                                ███  ████                              
░░███░░░░░███                              ░░░  ░░███                              
 ░███    ░███  ██████  ████████    ██████  ████  ░███   ███████  ██████  ████████  
 ░██████████  ███░░███░░███░░███  ███░░███░░███  ░███  ███░░███ ███░░███░░███░░███ 
 ░███░░░░░░  ░███████  ░███ ░███ ░███ ░░░  ░███  ░███ ░███ ░███░███ ░███ ░███ ░███ 
 ░███        ░███░░░   ░███ ░███ ░███  ███ ░███  ░███ ░███ ░███░███ ░███ ░███ ░███ 
 █████       ░░██████  ████ █████░░██████  █████ █████░░███████░░██████  ████ █████
░░░░░         ░░░░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░ ░░░░░  ░░░░░███ ░░░░░░  ░░░░ ░░░░░ 
                                                       ███ ░███                    
                                                      ░░██████                     
                                                       ░░░░░░                      
`

	bannerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Bold(true) // Purple
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)  // Pink
	textStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))              // Light gray/white
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Italic(true) // Dark comment gray

	var sb strings.Builder

	if m.state == stateMenu {
		// Custom styles for options
		optionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
		selectedOptionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)

		sb.WriteString(bannerStyle.Render(banner) + "\n")
		sb.WriteString("  " + titleStyle.Render("Welcome to \"Pencilgon\"") + "\n\n")
		sb.WriteString("  " + textStyle.Render("An XGBoost based tool for botnet detection.") + "\n\n")

		// Render options list
		options := []string{"Single file detection", "Folder detection"}
		for i, opt := range options {
			marker := "( )"
			if m.cursor == i {
				marker = "(•)"
			}

			line := "  " + marker + " " + opt
			if m.cursor == i {
				sb.WriteString(selectedOptionStyle.Render(line) + "\n")
			} else {
				sb.WriteString(optionStyle.Render(line) + "\n")
			}
		}

		sb.WriteString("\n  " + hintStyle.Render("Use up/down or j/k to navigate • Press Enter to select • 'q' to exit.") + "\n\n")

	} else if m.state == stateFileBrowser {
		sb.WriteString("  " + titleStyle.Render("Pencilgon File Explorer") + "\n\n")

		modeText := "Single file detection"
		if m.selectedOption == 1 {
			modeText = "Folder detection"
		}
		sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Render("Mode: "+modeText) + "\n")
		sb.WriteString("  " + textStyle.Render("Current Directory: "+m.currentDir) + "\n\n")

		// Styling for browser list
		selectedLineStyle := lipgloss.NewStyle().Background(lipgloss.Color("#44475A")).Foreground(lipgloss.Color("#FF79C6")).Bold(true)
		dirStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD")).Bold(true) // Cyan
		fileStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))           // Gray/White

		if len(m.entries) == 0 {
			sb.WriteString("    (Empty Directory)\n")
		} else {
			maxEntries := 10 // beyond a certain point: default to 10
			if m.height > 0 {
				maxEntries = m.height - 15
				if maxEntries < 3 {
					maxEntries = 3
				}
			}

			start := 0
			end := len(m.entries)
			if len(m.entries) > maxEntries {
				start = m.fileCursor - maxEntries/2
				if start < 0 {
					start = 0
				}
				end = start + maxEntries
				if end > len(m.entries) {
					end = len(m.entries)
					start = end - maxEntries
				}
			}

			var lines []string
			for i := start; i < end; i++ {
				entry := m.entries[i]
				icon := "📁"
				if !entry.IsDir {
					ext := strings.ToLower(filepath.Ext(entry.Name))
					if ext == ".json" || ext == ".ndjson" || ext == ".pcap" {
						icon = "📊" // Distinct icon for json/ndjson/pcap files
					} else {
						icon = "📄"
					}
				}

				var nameStr string
				if entry.IsDir {
					nameStr = dirStyle.Render(entry.Name)
				} else {
					nameStr = fileStyle.Render(entry.Name)
				}

				sizeStr := ""
				if !entry.IsDir {
					sizeStr = " (" + formatSize(entry.Size) + ")"
				}

				lineContent := icon + " " + nameStr + sizeStr

				var formattedLine string
				if m.fileCursor == i {
					formattedLine = selectedLineStyle.Render("  > " + lineContent)
				} else {
					formattedLine = "    " + lineContent
				}
				lines = append(lines, formattedLine)
			}

			if len(m.entries) > maxEntries {
				targetWidth := 0
				for _, line := range lines {
					w := lipgloss.Width(line)
					if w > targetWidth {
						targetWidth = w
					}
				}
				if m.width > 0 {
					innerWidth := m.width - 10
					if innerWidth > targetWidth {
						targetWidth = innerWidth
					}
				}
				lines = drawWithScrollbar(lines, start, len(lines), len(m.entries), targetWidth)
			}

			for _, line := range lines {
				sb.WriteString(line + "\n")
			}
		}

		// Dedicated action footer with bright green text
		var actionHintText string
		if m.selectedOption == 0 {
			actionHintText = "Press 'x' to select highlighted file for scanning"
		} else {
			actionHintText = "Press 'x' to scan highlighted folder"
		}
		actionHintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Italic(true).Bold(true)
		sb.WriteString("\n  " + actionHintStyle.Render(actionHintText) + "\n")

		// Standard navigation footer
		scrollText := ""
		if len(m.entries) > 0 {
			maxEntries := 10
			if m.height > 0 {
				maxEntries = m.height - 15
				if maxEntries < 3 {
					maxEntries = 3
				}
			}
			if len(m.entries) > maxEntries {
				start := m.fileCursor - maxEntries/2
				if start < 0 {
					start = 0
				}
				end := start + maxEntries
				if end > len(m.entries) {
					end = len(m.entries)
					start = end - maxEntries
				}
				scrollText = fmt.Sprintf(" • [Showing %d-%d of %d]", start+1, end, len(m.entries))
			}
		}
		sb.WriteString("  " + hintStyle.Render("Use ↑/↓ or j/k to navigate • Enter to open folder • Backspace to go up • Esc to return"+scrollText) + "\n\n")

	} else if m.state == stateConfirmSelection {
		sb.WriteString("  " + titleStyle.Render("Confirm Scan Action") + "\n\n")

		fileName := filepath.Base(m.scanPath)
		var promptText string
		if m.selectedOption == 1 {
			promptText = fmt.Sprintf("Proceed with scanning folder %s?", fileName)
		} else {
			promptText = fmt.Sprintf("Proceed with %s?", fileName)
		}
		sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true).Render(promptText) + "\n\n")

		if m.selectedOption == 1 {
			statsStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD"))
			sb.WriteString("  Detected in folder:\n")
			sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 JSON files:   %d", m.scanJSONCount)) + "\n")
			sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 NDJSON files: %d", m.scanNDJSONCount)) + "\n")
			sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 PCAP files:   %d", m.scanPCAPCount)) + "\n\n")
		}

		// Stylized choices
		yesStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true)
		noStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)

		sb.WriteString("    " + yesStyle.Render("[y] Yes, start scanning") + "\n")
		sb.WriteString("    " + noStyle.Render("[n] No, cancel") + "\n\n")

		sb.WriteString("  " + hintStyle.Render("Press 'y' to confirm scan, or 'n'/Esc to go back.") + "\n\n")

	} else if m.state == stateScanning {
		sb.WriteString(bannerStyle.Render(banner) + "\n")
		sb.WriteString("  " + titleStyle.Render("Pencilgon Scan in Progress...") + "\n\n")

		fileName := filepath.Base(m.scanPath)
		sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Scanning Target: %s", fileName)) + "\n")

		if m.selectedOption == 1 {
			sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Contains: %d JSON, %d NDJSON, %d PCAP files", m.scanJSONCount, m.scanNDJSONCount, m.scanPCAPCount)) + "\n")
		}

		sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Total Scan Size: %s", formatSize(m.scanTotalBytes))) + "\n")
		sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Bytes Processed: %s", formatSize(m.scanReadBytes))) + "\n\n")

		// Compute dynamic percentages
		pct := 0.0
		if m.scanTotalBytes > 0 {
			pct = float64(m.scanReadBytes) / float64(m.scanTotalBytes) * 100.0
		}
		if pct > 100.0 {
			pct = 100.0
		}

		barLength := 40
		completed := int(pct / 100.0 * float64(barLength))
		if completed > barLength {
			completed = barLength
		}
		if completed < 0 {
			completed = 0
		}
		remaining := barLength - completed

		greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true) // Dracula Green
		grayStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4"))             // Dracula Dark Gray

		bar := "[" + greenStyle.Render(strings.Repeat("█", completed)) + grayStyle.Render(strings.Repeat("░", remaining)) + "]"
		pctStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)

		sb.WriteString(fmt.Sprintf("  Progress: %s  %s\n\n", bar, pctStyle.Render(fmt.Sprintf("%.1f%%", pct))))
		sb.WriteString("  " + hintStyle.Render("Please wait, Pencilgon is analyzing network records...") + "\n\n")

	} else if m.state == stateResults {
		sb.WriteString("  " + titleStyle.Render("Pencilgon Scan Results") + "\n\n")

		fileName := filepath.Base(m.scanPath)
		sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Render("Target: "+fileName) + "\n")

		if m.scanError != nil {
			sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true).Render("Scan Failed:") + "\n")
			sb.WriteString("  " + textStyle.Render(m.scanError.Error()) + "\n\n")
		} else {
			// Count Botnet IPs
			var botnetCount int
			for _, res := range m.scanResults {
				if res.IsBotnet {
					botnetCount++
				}
			}

			sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Processed Records: %d", m.totalRecords)) + "\n")
			sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Botnet IPs Identified: %d (out of %d total communicating IPs)", botnetCount, len(m.scanResults))) + "\n\n")

			sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true).Render("Top 10 Highest Scored IPs:") + "\n")

			limit := 10
			if len(m.scanResults) < limit {
				limit = len(m.scanResults)
			}

			if limit == 0 {
				sb.WriteString("    (No communicating IPs found)\n")
			} else {
				for i := 0; i < limit; i++ {
					res := m.scanResults[i]
					var typeStr string
					var typeColor string
					if res.IsBotnet {
						typeStr = "BOTNET"
						typeColor = "#FF5555" // Dracula Red
					} else {
						typeStr = "BENIGN"
						typeColor = "#50FA7B" // Dracula Green
					}

					label := fmt.Sprintf("  %2d. IP: %-15s | ML Probability: %6.2f%% | ", i+1, res.IP, res.Probability)
					sb.WriteString(label + lipgloss.NewStyle().Foreground(lipgloss.Color(typeColor)).Bold(true).Render(typeStr) + "\n")
				}
			}
			sb.WriteString("\n")
		}

		// Dedicated action footer with bright green text
		if m.scanError == nil {
			actionHintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Italic(true).Bold(true)
			sb.WriteString("  " + actionHintStyle.Render("Press 'x' to see full scrollable log inside TUI") + "\n")
		}

		// Standard navigation footer
		sb.WriteString("  " + hintStyle.Render("Press Esc to return to directory explorer • 'q' to exit") + "\n\n")

	} else if m.state == stateFullLog {
		sb.WriteString("  " + titleStyle.Render("Pencilgon Full Scan Log") + "\n\n")

		lines := strings.Split(m.fullLogText, "\n")
		maxLinesToShow := 18
		if m.height > 0 {
			maxLinesToShow = m.height - 10
			if maxLinesToShow < 5 {
				maxLinesToShow = 5
			}
		}

		// Bounds check
		maxScroll := len(lines) - maxLinesToShow
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.logScrollRow > maxScroll {
			m.logScrollRow = maxScroll
		}
		if m.logScrollRow < 0 {
			m.logScrollRow = 0
		}

		endIndex := m.logScrollRow + maxLinesToShow
		if endIndex > len(lines) {
			endIndex = len(lines)
		}

		// Render scrollable log lines
		var visibleLines []string
		logLineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
		for i := m.logScrollRow; i < endIndex; i++ {
			visibleLines = append(visibleLines, "  "+logLineStyle.Render(lines[i]))
		}

		if len(lines) > maxLinesToShow {
			targetWidth := 0
			for _, line := range visibleLines {
				w := lipgloss.Width(line)
				if w > targetWidth {
					targetWidth = w
				}
			}
			if m.width > 0 {
				innerWidth := m.width - 10
				if innerWidth > targetWidth {
					targetWidth = innerWidth
				}
			}
			visibleLines = drawWithScrollbar(visibleLines, m.logScrollRow, len(visibleLines), len(lines), targetWidth)
		}

		for _, line := range visibleLines {
			sb.WriteString(line + "\n")
		}

		// Scroll indicator bar with green accent
		scrollPct := 0.0
		if len(lines) > maxLinesToShow {
			scrollPct = float64(m.logScrollRow) / float64(len(lines)-maxLinesToShow) * 100.0
		}

		scrollBarColor := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true)
		sb.WriteString("\n  " + scrollBarColor.Render(fmt.Sprintf("[Line %d-%d of %d (%.0f%%)]", m.logScrollRow+1, endIndex, len(lines), scrollPct)) + "\n")

		// Standard navigation footer
		sb.WriteString("  " + hintStyle.Render("Use ↑/↓ or j/k to scroll • Space/PageDown to scroll faster • Esc to return to summary") + "\n\n")
	}

	// Render within an elegant border
	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#BD93F9")).
		Padding(1, 2, 1, 2).
		Margin(1, 2)

	return borderStyle.Render(sb.String())
}

// padLine pads a string containing ANSI escape codes to a specific visual width.
func padLine(s string, width int) string {
	visualLen := lipgloss.Width(s)
	if visualLen >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visualLen)
}

// drawWithScrollbar renders a list of items with a vertical scrollbar on the right side.
func drawWithScrollbar(items []string, visibleStart, visibleCount, totalItems int, width int) []string {
	if totalItems <= visibleCount {
		return items
	}

	trackHeight := visibleCount
	if trackHeight <= 0 {
		return items
	}

	// Thumb size is proportional to visible items, at least 1 line
	thumbHeight := int(float64(visibleCount) * float64(visibleCount) / float64(totalItems))
	if thumbHeight < 1 {
		thumbHeight = 1
	}
	if thumbHeight > trackHeight {
		thumbHeight = trackHeight
	}

	// Thumb position is proportional to scroll position
	maxScroll := totalItems - visibleCount
	scrollFraction := 0.0
	if maxScroll > 0 {
		scrollFraction = float64(visibleStart) / float64(maxScroll)
	}

	thumbStart := int(scrollFraction * float64(trackHeight-thumbHeight))
	if thumbStart < 0 {
		thumbStart = 0
	}
	if thumbStart+thumbHeight > trackHeight {
		thumbStart = trackHeight - thumbHeight
	}

	scrollbarColor := lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")) // Purple track
	thumbStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6"))     // Pink thumb

	res := make([]string, len(items))
	for i := 0; i < len(items); i++ {
		char := "│"
		if i >= thumbStart && i < thumbStart+thumbHeight {
			char = "█"
		}

		styledChar := ""
		if char == "█" {
			styledChar = thumbStyle.Render(char)
		} else {
			styledChar = scrollbarColor.Render(char)
		}

		res[i] = padLine(items[i], width) + " " + styledChar
	}
	return res
}

// formatSize formats bytes into a human readable size.
func formatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

var ProgramOptions []tea.ProgramOption

// Start launches the Bubble Tea program and returns the confirmed path to scan.
func Start() (string, error) {
	// Mute global log outputs to prevent TUI terminal scrolling/drawing corruption
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
