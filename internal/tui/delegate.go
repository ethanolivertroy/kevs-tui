package tui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

// VulnDelegate is a custom delegate for rendering vulnerability items
type VulnDelegate struct {
	ShowDescription bool
	Styles          VulnDelegateStyles
}

// VulnDelegateStyles contains the styles for the delegate
type VulnDelegateStyles struct {
	NormalTitle    lipgloss.Style
	NormalDesc     lipgloss.Style
	SelectedTitle  lipgloss.Style
	SelectedDesc   lipgloss.Style
	DimmedTitle    lipgloss.Style
	DimmedDesc     lipgloss.Style
	CVEStyle       lipgloss.Style
	RansomwareIcon lipgloss.Style
}

// NewVulnDelegate creates a new delegate with default styles
func NewVulnDelegate() VulnDelegate {
	return VulnDelegate{
		ShowDescription: true,
		Styles: VulnDelegateStyles{
			NormalTitle:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")),
			NormalDesc:     lipgloss.NewStyle().Foreground(SubtleColor),
			SelectedTitle:  lipgloss.NewStyle().Foreground(PrimaryColor).Bold(true),
			SelectedDesc:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")),
			DimmedTitle:    lipgloss.NewStyle().Foreground(SubtleColor),
			DimmedDesc:     lipgloss.NewStyle().Foreground(SubtleColor),
			CVEStyle:       lipgloss.NewStyle().Foreground(SecondaryColor).Bold(true),
			RansomwareIcon: lipgloss.NewStyle().Foreground(RansomwareColor),
		},
	}
}

// Height returns the height of each item
func (d VulnDelegate) Height() int {
	if d.ShowDescription {
		return 2
	}
	return 1
}

// Spacing returns the spacing between items
func (d VulnDelegate) Spacing() int {
	return 1
}

// Update handles item updates
func (d VulnDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd {
	return nil
}

// Render renders a single item
func (d VulnDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	vuln, ok := item.(model.VulnerabilityItem)
	if !ok {
		return
	}

	isSelected := index == m.Index()
	isFiltering := m.FilterState() == list.Filtering

	var titleStyle, descStyle, cveStyle lipgloss.Style
	if isFiltering {
		titleStyle = d.Styles.DimmedTitle
		descStyle = d.Styles.DimmedDesc
		cveStyle = d.Styles.DimmedTitle
	} else if isSelected {
		titleStyle = d.Styles.SelectedTitle
		descStyle = d.Styles.SelectedDesc
		cveStyle = d.Styles.CVEStyle
	} else {
		titleStyle = d.Styles.NormalTitle
		descStyle = d.Styles.NormalDesc
		cveStyle = d.Styles.CVEStyle
	}

	// Build the title line with CVE prefix
	cvePrefix := cveStyle.Render(fmt.Sprintf("[%s]", vuln.CVEID))
	title := titleStyle.Render(" " + vuln.Title())

	// Add indicators
	indicators := ""

	// EPSS score indicator
	if vuln.EPSS.Score > 0 {
		indicators += " " + EPSSBadge(vuln.EPSS.Score)
	}

	// Ransomware indicator
	if vuln.RansomwareUse {
		indicators += d.Styles.RansomwareIcon.Render(" [R]")
	}

	// Overdue indicator
	if vuln.IsOverdue() {
		indicators += " " + lipgloss.NewStyle().Foreground(OverdueColor).Bold(true).Render("[!]")
	}

	line := cvePrefix + title + indicators

	if isSelected {
		line = SelectedItemStyle.Render(line)
	} else {
		line = NormalItemStyle.Render(line)
	}

	fmt.Fprint(w, line)

	if d.ShowDescription {
		// Enhanced description with EPSS bar
		descText := vuln.Description()
		if vuln.EPSS.Score > 0 {
			descText = fmt.Sprintf("%s | EPSS: %s", descText, EPSSBar(vuln.EPSS.Score, 10))
		}
		desc := descStyle.Render(descText)
		if isSelected {
			desc = SelectedItemStyle.Render(desc)
		} else {
			desc = NormalItemStyle.Render(desc)
		}
		fmt.Fprint(w, "\n"+desc)
	}
}
