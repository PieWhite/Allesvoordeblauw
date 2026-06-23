/*
Package tui implements a Bubble Tea-based Terminal User Interface (TUI)
for Pencilgon, an XGBoost-based tool for botnet detection.

This file handles model state view rendering and Dracula-themed lipgloss definitions.
*/
package tui

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"goversion/utils"

	"github.com/charmbracelet/lipgloss"
)

var (
	bannerStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Bold(true)
	titleStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)
	textStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
	hintStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Italic(true)
	optionStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
	selectedOptionStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)
	selectedLineStyle   = lipgloss.NewStyle().Background(lipgloss.Color("#44475A")).Foreground(lipgloss.Color("#FF79C6")).Bold(true)
	dirStyle            = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD")).Bold(true)
	fileStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
	actionHintStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Italic(true).Bold(true)
	yesStyle            = lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true)
	noStyle             = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)
	statsStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD"))
	greenStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true)
	grayStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4"))
	pctStyle            = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)
	warningStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true).Italic(true)
	unselectedLineStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
	scrollbarColor      = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9"))
	thumbStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6"))
	borderStyle         = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#BD93F9")).Padding(1, 2, 1, 2).Margin(1, 2)
)

const banner = `
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

func (m Model) View() string {
	if m.quitting {
		return "\n  Goodbye from Pencilgon!\n\n"
	}

	var sb strings.Builder
	switch m.state {
	case stateMenu:
		m.renderMenu(&sb)
	case stateFileBrowser:
		m.renderFileBrowser(&sb)
	case stateConfirmSelection:
		m.renderConfirmSelection(&sb)
	case stateScanning:
		m.renderScanning(&sb)
	case stateResults:
		m.renderResults(&sb)
	case stateFullLog:
		m.renderFullLog(&sb)
	case stateConfiguration:
		m.renderConfiguration(&sb)
	}

	return borderStyle.Render(sb.String())
}

func (m *Model) renderMenu(sb *strings.Builder) {
	sb.WriteString(bannerStyle.Render(banner) + "\n")
	sb.WriteString("  " + titleStyle.Render("Welcome to \"Pencilgon\"") + "\n\n")
	sb.WriteString("  " + textStyle.Render("An XGBoost based tool for botnet detection.") + "\n\n")

	options := []string{"Single file detection", "Folder detection", "Configuration"}
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
}

func (m *Model) renderFileBrowser(sb *strings.Builder) {
	sb.WriteString("  " + titleStyle.Render("Pencilgon File Explorer") + "\n\n")

	modeText := "Single file detection"
	if m.selectedOption == 1 {
		modeText = "Folder detection"
	}
	sb.WriteString("  " + bannerStyle.Render("Mode: "+modeText) + "\n")
	sb.WriteString("  " + textStyle.Render("Current Directory: "+m.currentDir) + "\n\n")

	if len(m.entries) == 0 {
		sb.WriteString("    (Empty Directory)\n")
	} else {
		pageSize := 10
		currentPage := m.fileCursor / pageSize
		start := currentPage * pageSize
		end := start + pageSize
		if end > len(m.entries) {
			end = len(m.entries)
		}

		var lines []string
		for i := start; i < end; i++ {
			entry := m.entries[i]
			icon := "📁"
			if !entry.IsDir {
				ext := strings.ToLower(filepath.Ext(entry.Name))
				if ext == ".json" || ext == ".ndjson" || ext == ".pcap" || ext == ".csv" {
					icon = "📊"
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

		if len(m.entries) > pageSize {
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

	var actionHintText string
	if m.selectedOption == 0 {
		actionHintText = "Press 'x' to select highlighted file for scanning"
	} else {
		actionHintText = "Press 'x' to scan highlighted folder"
	}
	sb.WriteString("\n  " + actionHintStyle.Render(actionHintText) + "\n")

	scrollText := ""
	if len(m.entries) > 0 {
		pageSize := 10
		totalPages := (len(m.entries) + pageSize - 1) / pageSize
		currentPage := m.fileCursor / pageSize
		start := currentPage * pageSize
		end := start + pageSize
		if end > len(m.entries) {
			end = len(m.entries)
		}
		scrollText = fmt.Sprintf(" • [Page %d/%d (Items %d-%d of %d)]", currentPage+1, totalPages, start+1, end, len(m.entries))
	}
	sb.WriteString("  " + hintStyle.Render("Use ↑/↓ or j/k to navigate • ←/→ or h/l to page • Enter to open folder • Backspace to go up • Esc to return"+scrollText) + "\n\n")
}

func (m *Model) renderConfirmSelection(sb *strings.Builder) {
	sb.WriteString("  " + titleStyle.Render("Confirm Scan Action") + "\n\n")

	fileName := filepath.Base(m.scanPath)
	var promptText string
	if m.selectedOption == 1 {
		promptText = fmt.Sprintf("Proceed with scanning folder %s?", fileName)
	} else {
		promptText = fmt.Sprintf("Proceed with %s?", fileName)
	}
	sb.WriteString("  " + noStyle.Render(promptText) + "\n\n")

	if m.selectedOption == 1 {
		sb.WriteString("  Detected in folder:\n")
		sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 JSON files:   %d", m.scanJSONCount)) + "\n")
		sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 NDJSON files: %d", m.scanNDJSONCount)) + "\n")
		sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 PCAP files:   %d", m.scanPCAPCount)) + "\n")
		sb.WriteString(statsStyle.Render(fmt.Sprintf("    📊 CSV files:    %d", m.scanCSVCount)) + "\n\n")
	}

	sb.WriteString("    " + yesStyle.Render("[y] Yes, start scanning") + "\n")
	sb.WriteString("    " + noStyle.Render("[n] No, cancel") + "\n\n")

	sb.WriteString("  " + hintStyle.Render("Press 'y' to confirm scan, or 'n'/Esc to go back.") + "\n\n")
}

func (m *Model) renderScanning(sb *strings.Builder) {
	sb.WriteString(bannerStyle.Render(banner) + "\n")
	sb.WriteString("  " + titleStyle.Render("Pencilgon Scan in Progress...") + "\n\n")

	fileName := filepath.Base(m.scanPath)
	sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Scanning Target: %s", fileName)) + "\n")

	if m.selectedOption == 1 {
		sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Contains: %d JSON, %d NDJSON, %d PCAP, %d CSV files", m.scanJSONCount, m.scanNDJSONCount, m.scanPCAPCount, m.scanCSVCount)) + "\n")
	}

	sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Total Scan Size:    %s", formatSize(m.scanTotalBytes))) + "\n")
	sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Bytes Processed:    %s", formatSize(m.scanReadBytes))) + "\n")
	sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Records Decoded:    %d", m.scanRecordsDecoded)) + "\n")
	sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Records Aggregated: %d", m.scanRecordsAggregated)) + "\n")
	sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Windows Inferred:   %d", m.scanWindowsInferred)) + "\n\n")

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

	bar := "[" + greenStyle.Render(strings.Repeat("█", completed)) + grayStyle.Render(strings.Repeat("░", remaining)) + "]"

	sb.WriteString(fmt.Sprintf("  Progress: %s  %s\n\n", bar, pctStyle.Render(fmt.Sprintf("%.1f%%", pct))))
	sb.WriteString("  " + hintStyle.Render("Please wait, Pencilgon is analyzing network records...") + "\n\n")
}

func (m *Model) renderResults(sb *strings.Builder) {
	sb.WriteString("  " + titleStyle.Render("Pencilgon Scan Results") + "\n\n")

	fileName := filepath.Base(m.scanPath)
	sb.WriteString("  " + bannerStyle.Render("Target: "+fileName) + "\n")

	if m.scanError != nil {
		sb.WriteString("  " + noStyle.Render("Scan Failed:") + "\n")
		sb.WriteString("  " + textStyle.Render(m.scanError.Error()) + "\n\n")
	} else {
		var botnetCount int
		for _, res := range m.scanResults {
			if res.IsBotnet {
				botnetCount++
			}
		}

		sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Processed Records: %d", m.totalRecords)) + "\n")
		sb.WriteString("  " + textStyle.Render(fmt.Sprintf("Botnet IPs Identified: %d (out of %d total communicating IPs)", botnetCount, m.totalCommunicatingIPs)) + "\n\n")

		sb.WriteString("  " + pctStyle.Render("Top 10 Highest Scored IPs:") + "\n")

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
					typeColor = "#FF5555"
				} else {
					typeStr = "BENIGN"
					typeColor = "#50FA7B"
				}

				label := fmt.Sprintf("  %2d. IP: %-15s | ML Probability: %6.2f%% | ", i+1, res.IP, res.Probability)
				sb.WriteString(label + lipgloss.NewStyle().Foreground(lipgloss.Color(typeColor)).Bold(true).Render(typeStr) + "\n")
			}
		}
		sb.WriteString("\n")
	}

	if m.scanError == nil {
		sb.WriteString("  " + actionHintStyle.Render("Press 'x' to see full scrollable log inside TUI") + "\n")
	}

	sb.WriteString("  " + hintStyle.Render("Press Esc to return to directory explorer • 'q' to exit") + "\n\n")
}

func (m *Model) renderFullLog(sb *strings.Builder) {
	sb.WriteString("  " + titleStyle.Render("Pencilgon Full Scan Log") + "\n\n")

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

	var visibleLines []string
	for i := m.logScrollRow; i < endIndex; i++ {
		visibleLines = append(visibleLines, "  "+unselectedLineStyle.Render(lines[i]))
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

	scrollPct := 0.0
	if len(lines) > maxLinesToShow {
		scrollPct = float64(m.logScrollRow) / float64(len(lines)-maxLinesToShow) * 100.0
	}

	sb.WriteString("\n  " + actionHintStyle.Render(fmt.Sprintf("[Line %d-%d of %d (%.0f%%)]", m.logScrollRow+1, endIndex, len(lines), scrollPct)) + "\n")
	sb.WriteString("  " + hintStyle.Render("Use ↑/↓ or j/k to scroll • Space/PageDown to scroll faster • Esc to return to summary") + "\n\n")
}

func (m *Model) renderConfiguration(sb *strings.Builder) {
	sb.WriteString("  " + titleStyle.Render("Pencilgon Concurrency Configuration") + "\n\n")
	sb.WriteString("  ⚠️  " + warningStyle.Render("(IT'S RECOMMENDED TO KEEP THE DEFAULT SETTINGS, FOR SOME SYSTEMS LOWERING THE VALUES CAN IMPROVE PERFORMANCE)") + "\n\n")

	cores := runtime.NumCPU()
	recPlan := utils.GetRecommendedPlan()

	sb.WriteString("  " + statsStyle.Render("Detected Hardware Profile:") + "\n")
	sb.WriteString(textStyle.Render(fmt.Sprintf("    • Logical CPU Cores:        %d", cores)) + "\n")
	sb.WriteString(textStyle.Render(fmt.Sprintf("    • Recommended Files:        %d", recPlan.ConcurrentFiles)) + "\n")
	sb.WriteString(textStyle.Render(fmt.Sprintf("    • Recommended Workers/File: %d", recPlan.WorkersPerFile)) + "\n\n")

	sb.WriteString("  " + statsStyle.Render("Adjust Concurrency Parameters:") + "\n")

	renderRow := func(index int, label string) string {
		marker := "   "
		if m.cfgCursor == index {
			marker = " > "
			return selectedOptionStyle.Render(marker + label)
		}
		return unselectedLineStyle.Render(marker + label)
	}

	filesVal := fmt.Sprintf("◄ %d ►", m.cfgConcurrentFiles)
	if m.cfgConcurrentFiles <= 1 {
		filesVal = fmt.Sprintf("  %d ►", m.cfgConcurrentFiles)
	}
	sb.WriteString(renderRow(0, fmt.Sprintf("Concurrent Files (Directory Level):  %s", filesVal)) + "\n")

	workersVal := fmt.Sprintf("◄ %d ►", m.cfgWorkersPerFile)
	if m.cfgWorkersPerFile <= 1 {
		workersVal = fmt.Sprintf("  %d ►", m.cfgWorkersPerFile)
	}
	sb.WriteString(renderRow(1, fmt.Sprintf("Workers Per File (Parser Level):     %s", workersVal)) + "\n\n")

	subnetVal := m.cfgSubnet
	if subnetVal == "" {
		subnetVal = "(None - parse all IPs)"
	}
	var subnetRowText string
	if m.cfgCursor == 2 {
		subnetRowText = fmt.Sprintf("IP Subnet Filter (type to edit):     %s█", m.cfgSubnet)
	} else {
		subnetRowText = fmt.Sprintf("IP Subnet Filter:                    %s", subnetVal)
	}
	sb.WriteString(renderRow(2, subnetRowText) + "\n\n")

	sb.WriteString(renderRow(3, "[ Save & Apply Changes ]") + "\n")
	sb.WriteString(renderRow(4, "[ Reset to Hardware Defaults ]") + "\n")
	sb.WriteString(renderRow(5, "[ Cancel & Go Back ]") + "\n\n")

	if m.cfgCursor == 2 {
		sb.WriteString("  " + hintStyle.Render("Use ↑/↓ to navigate • Type characters to edit (e.g. 192.251.x.x) • Backspace to erase • Esc to back") + "\n\n")
	} else {
		sb.WriteString("  " + hintStyle.Render("Use ↑/↓ or j/k to navigate • ←/→ or h/l to adjust values • Enter to select • Esc to back") + "\n\n")
	}
}
