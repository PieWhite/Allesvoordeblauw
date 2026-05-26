package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Model defines the state of our TUI.
type Model struct {
	quitting bool
}

// NewModel initializes the TUI model.
func NewModel() Model {
	return Model{}
}

// Init initializes the Bubble Tea loop.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles message updates in the Bubble Tea loop.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
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

	// Color palette (Dracula / Cyberpunk inspired)
	bannerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Bold(true) // Purple
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Bold(true)  // Pink
	textStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))              // Light gray/white
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Italic(true) // Dark comment gray

	// Assemble view components
	var sb strings.Builder
	sb.WriteString(bannerStyle.Render(banner) + "\n")
	sb.WriteString("  " + titleStyle.Render("Welcome to \"Pencilgon\"") + "\n\n")
	sb.WriteString("  " + textStyle.Render("An XGBoost based tool for botnet detection.") + "\n")
	sb.WriteString("  " + hintStyle.Render("Press 'q' or 'Ctrl+C' to exit.") + "\n\n")

	// Render within a elegant border
	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#BD93F9")).
		Padding(1, 2, 1, 2).
		Margin(1, 2)

	return borderStyle.Render(sb.String())
}

// Start launches the Bubble Tea program.
func Start() error {
	p := tea.NewProgram(NewModel())
	_, err := p.Run()
	return err
}
