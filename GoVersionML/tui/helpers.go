/*
Package tui implements a Bubble Tea-based Terminal User Interface (TUI)
for Pencilgon, an XGBoost-based tool for botnet detection.

This file provides formatting and scrollbar drawing helper utilities for TUI.
*/
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func padLine(s string, width int) string {
	visualLen := lipgloss.Width(s)
	if visualLen >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visualLen)
}

func drawWithScrollbar(items []string, visibleStart, visibleCount, totalItems int, width int) []string {
	if totalItems <= visibleCount {
		return items
	}

	trackHeight := visibleCount
	if trackHeight <= 0 {
		return items
	}

	thumbHeight := int(float64(visibleCount) * float64(visibleCount) / float64(totalItems))
	if thumbHeight < 1 {
		thumbHeight = 1
	}
	if thumbHeight > trackHeight {
		thumbHeight = trackHeight
	}

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
