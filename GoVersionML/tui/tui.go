package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type sessionState int

const (
	stateMenu sessionState = iota
	stateFileBrowser
	stateConfirmSelection
)

// FileEntry represents a file or directory item.
type FileEntry struct {
	Name  string
	IsDir bool
	Size  int64
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
	scanPath      string
	confirmedScan bool
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

// Update handles message updates in the Bubble Tea loop.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "esc":
			if m.state == stateConfirmSelection {
				m.state = stateFileBrowser
				m.scanPath = ""
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
							if ext == ".json" || ext == ".ndjson" {
								m.scanPath = filepath.Join(m.currentDir, entry.Name)
								m.state = stateConfirmSelection
							}
						}
					} else if m.selectedOption == 1 {
						if entry.IsDir && entry.Name != ".." {
							m.scanPath = filepath.Join(m.currentDir, entry.Name)
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
				return m, tea.Quit
			case "n", "N":
				m.state = stateFileBrowser
				m.scanPath = ""
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
			for i, entry := range m.entries {
				icon := "📁"
				if !entry.IsDir {
					ext := strings.ToLower(filepath.Ext(entry.Name))
					if ext == ".json" || ext == ".ndjson" {
						icon = "📊" // Distinct icon for json/ndjson files
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

				if m.fileCursor == i {
					sb.WriteString(selectedLineStyle.Render("  > "+lineContent) + "\n")
				} else {
					sb.WriteString("    "+lineContent + "\n")
				}
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
		sb.WriteString("  " + hintStyle.Render("Use ↑/↓ or j/k to navigate • Enter to open folder • Backspace to go up • Esc to return") + "\n\n")

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

		// Stylized choices
		yesStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true)
		noStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)

		sb.WriteString("    " + yesStyle.Render("[y] Yes, start scanning") + "\n")
		sb.WriteString("    " + noStyle.Render("[n] No, cancel") + "\n\n")

		sb.WriteString("  " + hintStyle.Render("Press 'y' to confirm scan, or 'n'/Esc to go back.") + "\n\n")
	}

	// Render within an elegant border
	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#BD93F9")).
		Padding(1, 2, 1, 2).
		Margin(1, 2)

	return borderStyle.Render(sb.String())
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

// Start launches the Bubble Tea program and returns the confirmed path to scan if selected.
func Start() (string, error) {
	m := NewModel()
	p := tea.NewProgram(m)
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
