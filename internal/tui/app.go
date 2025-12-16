package tui

import (
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethanolivertroy/kevs-tui/internal/api"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

// ViewState represents the current view
type ViewState int

const (
	ViewList ViewState = iota
	ViewDetail
	ViewChartsMenu
	ViewVendorChart
	ViewTimeline
	ViewRansomware
	ViewCWE
	ViewRisk
	ViewExportMenu
)

// ChartOption represents a chart in the charts menu
type ChartOption struct {
	Name        string
	Description string
	View        ViewState
}

// SortMode represents the current sort order
type SortMode int

const (
	SortByDateAdded SortMode = iota
	SortByDueDate
	SortByEPSS
	SortByVendor
)

func (s SortMode) String() string {
	switch s {
	case SortByDateAdded:
		return "Date Added"
	case SortByDueDate:
		return "Due Date"
	case SortByEPSS:
		return "EPSS Score"
	case SortByVendor:
		return "Vendor"
	}
	return ""
}

// FilterMode represents special filters
type FilterMode int

const (
	FilterNone FilterMode = iota
	FilterRansomware
	FilterOverdue
	FilterVendor
)

// Model is the main application model
type Model struct {
	list           list.Model
	allVulns       []model.Vulnerability
	filteredVulns  []list.Item
	spinner        spinner.Model
	loading        bool
	loadingEPSS    bool
	loadingCVSS    bool
	err            error
	width          int
	height         int
	view           ViewState
	selectedVuln   *model.VulnerabilityItem
	selectedCVSS   *model.CVSSData
	apiClient      *api.Client
	keys           KeyMap
	help           help.Model
	showHelp       bool
	viewport       viewport.Model
	viewportReady  bool
	sortMode       SortMode
	filterMode     FilterMode
	stats          Stats
	statusMsg      string
	// Vendor chart state
	vendorList          []VendorStats
	selectedVendorIndex int
	selectedVendorName  string
	// Charts menu state
	chartOptions       []ChartOption
	selectedChartIndex int
	// Export menu state
	exportOptions       []ExportOption
	selectedExportIndex int
}

// Stats holds statistics about the vulnerabilities
type Stats struct {
	Total      int
	Ransomware int
	Overdue    int
}

// Messages
type VulnsLoadedMsg struct {
	Vulns []model.Vulnerability
}

type EPSSLoadedMsg struct {
	Scores map[string]model.EPSSScore
}

type ErrorMsg struct {
	Err error
}

type StatusMsg struct {
	Msg string
}

type CVSSLoadedMsg struct {
	Data model.CVSSData
}

// NewModel creates a new application model
func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(PrimaryColor)

	h := help.New()
	h.ShowAll = false

	return Model{
		spinner:   s,
		loading:   true,
		apiClient: api.NewClient(),
		keys:      DefaultKeyMap(),
		help:      h,
		sortMode:  SortByDateAdded,
		chartOptions: []ChartOption{
			{Name: "Top Vendors", Description: "CVEs by vendor", View: ViewVendorChart},
			{Name: "Timeline", Description: "CVEs over time", View: ViewTimeline},
			{Name: "Ransomware", Description: "Ransomware campaign usage", View: ViewRansomware},
			{Name: "CWE Types", Description: "Top vulnerability types", View: ViewCWE},
			{Name: "Risk Distribution", Description: "EPSS-based risk levels", View: ViewRisk},
		},
		exportOptions: []ExportOption{
			{Name: "JSON (Current View)", Format: ExportJSON, Scope: ExportCurrentView},
			{Name: "JSON (Full Catalog)", Format: ExportJSON, Scope: ExportFullCatalog},
			{Name: "CSV (Current View)", Format: ExportCSV, Scope: ExportCurrentView},
			{Name: "CSV (Full Catalog)", Format: ExportCSV, Scope: ExportFullCatalog},
			{Name: "Markdown (Current View)", Format: ExportMarkdown, Scope: ExportCurrentView},
			{Name: "Markdown (Full Catalog)", Format: ExportMarkdown, Scope: ExportFullCatalog},
		},
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.fetchVulns())
}

func (m Model) fetchVulns() tea.Cmd {
	return func() tea.Msg {
		vulns, err := m.apiClient.FetchVulnerabilities()
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return VulnsLoadedMsg{Vulns: vulns}
	}
}

func (m Model) fetchEPSS(cveIDs []string) tea.Cmd {
	return func() tea.Msg {
		scores, err := m.apiClient.FetchEPSSScores(cveIDs)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return EPSSLoadedMsg{Scores: scores}
	}
}

func (m Model) fetchCVSS(cveID string) tea.Cmd {
	return func() tea.Msg {
		data, err := m.apiClient.FetchCVSSAll(cveID)
		if err != nil {
			// Don't fail on CVSS fetch error, just return empty
			return CVSSLoadedMsg{Data: model.CVSSData{}}
		}
		return CVSSLoadedMsg{Data: data}
	}
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Clear status message on any key press
		m.statusMsg = ""

		// Handle quit
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		// Global keys
		switch msg.String() {
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		}

		// If in list view and not filtering
		if m.view == ViewList && m.list.FilterState() != list.Filtering {
			switch msg.String() {
			case "q":
				return m, tea.Quit
			case "enter":
				if item, ok := m.list.SelectedItem().(model.VulnerabilityItem); ok {
					m.selectedVuln = &item
					m.selectedCVSS = nil
					m.loadingCVSS = true
					m.view = ViewDetail
					m.viewport = viewport.New(m.width-4, m.height-6)
					m.viewport.SetContent(m.renderDetailContent())
					m.viewportReady = true
					return m, tea.Batch(m.spinner.Tick, m.fetchCVSS(item.CVEID))
				}
			case "s":
				m.sortMode = (m.sortMode + 1) % 4
				m.applySortAndFilter()
				m.list.SetItems(m.filteredVulns)
				m.statusMsg = fmt.Sprintf("Sorted by: %s", m.sortMode.String())
				return m, nil
			case "r":
				if m.filterMode == FilterRansomware {
					m.filterMode = FilterNone
					m.statusMsg = "Filter cleared"
				} else {
					m.filterMode = FilterRansomware
					m.statusMsg = "Showing ransomware only"
				}
				m.applySortAndFilter()
				m.list.SetItems(m.filteredVulns)
				return m, nil
			case "d":
				if m.filterMode == FilterOverdue {
					m.filterMode = FilterNone
					m.statusMsg = "Filter cleared"
				} else {
					m.filterMode = FilterOverdue
					m.statusMsg = "Showing overdue only"
				}
				m.applySortAndFilter()
				m.list.SetItems(m.filteredVulns)
				return m, nil
			case "o":
				if item, ok := m.list.SelectedItem().(model.VulnerabilityItem); ok {
					openURL(item.NVDURL())
					m.statusMsg = "Opening in browser..."
					return m, nil
				}
			case "c":
				if item, ok := m.list.SelectedItem().(model.VulnerabilityItem); ok {
					copyToClipboard(item.CVEID)
					m.statusMsg = fmt.Sprintf("Copied: %s", item.CVEID)
					return m, nil
				}
			case "g":
				m.selectedChartIndex = 0
				m.view = ViewChartsMenu
				return m, nil
			case "G":
				// Jump to end of list (vim style)
				if len(m.list.Items()) > 0 {
					m.list.Select(len(m.list.Items()) - 1)
				}
				return m, nil
			case "home", "t":
				// Jump to start of list
				m.list.Select(0)
				return m, nil
			case "end", "b":
				// Jump to end of list
				if len(m.list.Items()) > 0 {
					m.list.Select(len(m.list.Items()) - 1)
				}
				return m, nil
			case "x":
				m.selectedExportIndex = 0
				m.view = ViewExportMenu
				return m, nil
			}
		}

		// If in detail view
		if m.view == ViewDetail {
			switch msg.String() {
			case "q", "esc", "backspace":
				m.view = ViewList
				m.selectedVuln = nil
				return m, nil
			case "o":
				if m.selectedVuln != nil {
					openURL(m.selectedVuln.NVDURL())
					m.statusMsg = "Opening NVD..."
					return m, nil
				}
			case "c":
				if m.selectedVuln != nil {
					copyToClipboard(m.selectedVuln.CVEID)
					m.statusMsg = fmt.Sprintf("Copied: %s", m.selectedVuln.CVEID)
					return m, nil
				}
			case "w":
				if m.selectedVuln != nil && len(m.selectedVuln.CWEs) > 0 {
					cweID := extractCWENumber(m.selectedVuln.CWEs[0])
					if cweID != "" {
						openURL("http://cwe.mitre.org/data/definitions/" + cweID + ".html")
						m.statusMsg = "Opening CWE..."
					}
					return m, nil
				}
			default:
				// Pass to viewport for scrolling
				if m.viewportReady {
					var cmd tea.Cmd
					m.viewport, cmd = m.viewport.Update(msg)
					return m, cmd
				}
			}
		}

		// If in charts menu view
		if m.view == ViewChartsMenu {
			switch msg.String() {
			case "q", "esc", "g", "backspace":
				m.view = ViewList
				return m, nil
			case "j", "down":
				m.selectedChartIndex = (m.selectedChartIndex + 1) % len(m.chartOptions)
				return m, nil
			case "k", "up":
				m.selectedChartIndex = (m.selectedChartIndex - 1 + len(m.chartOptions)) % len(m.chartOptions)
				return m, nil
			case "enter":
				selected := m.chartOptions[m.selectedChartIndex]
				if selected.View == ViewVendorChart {
					m.vendorList = GetTopVendors(m.allVulns, 10)
					m.selectedVendorIndex = 0
				}
				m.view = selected.View
				return m, nil
			}
		}

		// If in export menu view
		if m.view == ViewExportMenu {
			switch msg.String() {
			case "q", "esc", "x", "backspace":
				m.view = ViewList
				return m, nil
			case "j", "down":
				m.selectedExportIndex = (m.selectedExportIndex + 1) % len(m.exportOptions)
				return m, nil
			case "k", "up":
				m.selectedExportIndex = (m.selectedExportIndex - 1 + len(m.exportOptions)) % len(m.exportOptions)
				return m, nil
			case "enter":
				selected := m.exportOptions[m.selectedExportIndex]
				var vulns []model.Vulnerability
				if selected.Scope == ExportCurrentView {
					// Get current visible items (respects search filter)
					for _, item := range m.list.VisibleItems() {
						if vi, ok := item.(model.VulnerabilityItem); ok {
							vulns = append(vulns, vi.Vulnerability)
						}
					}
				} else {
					vulns = m.allVulns
				}

				// Export to current directory
				result := Export(vulns, selected.Format, ".")
				if result.Err != nil {
					m.statusMsg = fmt.Sprintf("Export failed: %v", result.Err)
				} else {
					m.statusMsg = fmt.Sprintf("Exported %d CVEs to %s", result.Count, result.FilePath)
				}
				m.view = ViewList
				return m, nil
			}
		}

		// If in vendor chart view
		if m.view == ViewVendorChart {
			switch msg.String() {
			case "q", "esc", "backspace":
				m.view = ViewChartsMenu
				return m, nil
			case "g":
				// Clear vendor filter if active and go to charts menu
				if m.filterMode == FilterVendor {
					m.filterMode = FilterNone
					m.selectedVendorName = ""
					m.applySortAndFilter()
					m.list.SetItems(m.filteredVulns)
				}
				m.view = ViewChartsMenu
				return m, nil
			case "j", "down":
				if len(m.vendorList) > 0 {
					m.selectedVendorIndex = (m.selectedVendorIndex + 1) % len(m.vendorList)
				}
				return m, nil
			case "k", "up":
				if len(m.vendorList) > 0 {
					m.selectedVendorIndex = (m.selectedVendorIndex - 1 + len(m.vendorList)) % len(m.vendorList)
				}
				return m, nil
			case "enter":
				if len(m.vendorList) > 0 && m.selectedVendorIndex < len(m.vendorList) {
					m.selectedVendorName = m.vendorList[m.selectedVendorIndex].Name
					m.filterMode = FilterVendor
					m.applySortAndFilter()
					m.list.SetItems(m.filteredVulns)
					m.statusMsg = fmt.Sprintf("Filtered: %s (%d CVEs)", m.selectedVendorName, m.vendorList[m.selectedVendorIndex].Count)
					m.view = ViewList
				}
				return m, nil
			}
		}

		// If in timeline view
		if m.view == ViewTimeline {
			switch msg.String() {
			case "q", "esc", "g", "backspace":
				m.view = ViewChartsMenu
				return m, nil
			}
		}

		// If in ransomware chart view
		if m.view == ViewRansomware {
			switch msg.String() {
			case "q", "esc", "g", "backspace":
				m.view = ViewChartsMenu
				return m, nil
			}
		}

		// If in CWE chart view
		if m.view == ViewCWE {
			switch msg.String() {
			case "q", "esc", "g", "backspace":
				m.view = ViewChartsMenu
				return m, nil
			}
		}

		// If in risk chart view
		if m.view == ViewRisk {
			switch msg.String() {
			case "q", "esc", "g", "backspace":
				m.view = ViewChartsMenu
				return m, nil
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width
		if !m.loading {
			headerHeight := 4 // Title + stats
			footerHeight := 2 // Help
			m.list.SetSize(msg.Width, msg.Height-headerHeight-footerHeight)
		}
		if m.viewportReady {
			m.viewport.Width = msg.Width - 4
			m.viewport.Height = msg.Height - 6
		}
		return m, nil

	case spinner.TickMsg:
		if m.loading || m.loadingEPSS || m.loadingCVSS {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}

	case VulnsLoadedMsg:
		m.loading = false
		m.allVulns = msg.Vulns
		m.calculateStats()
		m.applySortAndFilter()

		delegate := NewVulnDelegate()
		m.list = list.New(m.filteredVulns, delegate, m.width, m.height-6)
		m.list.Title = "CISA Known Exploited Vulnerabilities"
		m.list.SetShowStatusBar(true)
		m.list.SetFilteringEnabled(true)
		m.list.SetShowHelp(false) // Disable built-in help, we render our own
		m.list.Styles.Title = TitleStyle

		// Use exact substring matching
		m.list.Filter = func(term string, targets []string) []list.Rank {
			var ranks []list.Rank
			term = strings.ToLower(term)
			for i, target := range targets {
				if strings.Contains(strings.ToLower(target), term) {
					ranks = append(ranks, list.Rank{Index: i})
				}
			}
			return ranks
		}

		// Fetch EPSS scores
		m.loadingEPSS = true
		cveIDs := make([]string, len(msg.Vulns))
		for i, v := range msg.Vulns {
			cveIDs[i] = v.CVEID
		}
		return m, tea.Batch(m.spinner.Tick, m.fetchEPSS(cveIDs))

	case EPSSLoadedMsg:
		m.loadingEPSS = false
		// Update vulnerabilities with EPSS scores
		for i := range m.allVulns {
			if score, ok := msg.Scores[m.allVulns[i].CVEID]; ok {
				m.allVulns[i].EPSS = score
			}
		}
		m.applySortAndFilter()
		m.list.SetItems(m.filteredVulns)
		return m, nil

	case CVSSLoadedMsg:
		m.loadingCVSS = false
		if msg.Data.Primary != nil || len(msg.Data.Secondary) > 0 {
			m.selectedCVSS = &msg.Data
		}
		// Refresh the viewport content with CVSS data
		if m.viewportReady && m.selectedVuln != nil {
			m.viewport.SetContent(m.renderDetailContent())
		}
		return m, nil

	case ErrorMsg:
		m.loading = false
		m.loadingEPSS = false
		m.err = msg.Err
		return m, nil
	}

	// Update list if in list view
	if m.view == ViewList && !m.loading {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *Model) calculateStats() {
	m.stats.Total = len(m.allVulns)
	m.stats.Ransomware = 0
	m.stats.Overdue = 0
	for _, v := range m.allVulns {
		if v.RansomwareUse {
			m.stats.Ransomware++
		}
		if v.IsOverdue() {
			m.stats.Overdue++
		}
	}
}

func (m *Model) applySortAndFilter() {
	// Start with all vulns
	filtered := make([]model.Vulnerability, len(m.allVulns))
	copy(filtered, m.allVulns)

	// Apply filter
	switch m.filterMode {
	case FilterRansomware:
		var ransomware []model.Vulnerability
		for _, v := range filtered {
			if v.RansomwareUse {
				ransomware = append(ransomware, v)
			}
		}
		filtered = ransomware
	case FilterOverdue:
		var overdue []model.Vulnerability
		for _, v := range filtered {
			if v.IsOverdue() {
				overdue = append(overdue, v)
			}
		}
		filtered = overdue
	case FilterVendor:
		if m.selectedVendorName != "" {
			var vendorFiltered []model.Vulnerability
			for _, v := range filtered {
				if v.VendorProject == m.selectedVendorName {
					vendorFiltered = append(vendorFiltered, v)
				}
			}
			filtered = vendorFiltered
		}
	}

	// Apply sort
	switch m.sortMode {
	case SortByDateAdded:
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].DateAdded.After(filtered[j].DateAdded)
		})
	case SortByDueDate:
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].DueDate.Before(filtered[j].DueDate)
		})
	case SortByEPSS:
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].EPSS.Score > filtered[j].EPSS.Score
		})
	case SortByVendor:
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].VendorProject < filtered[j].VendorProject
		})
	}

	// Convert to list items
	m.filteredVulns = make([]list.Item, len(filtered))
	for i, v := range filtered {
		m.filteredVulns[i] = model.VulnerabilityItem{Vulnerability: v}
	}
}

// View renders the view
func (m Model) View() string {
	if m.loading {
		return fmt.Sprintf("\n  %s Loading KEV data...\n", m.spinner.View())
	}

	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v\n\n  Press q to quit.\n", m.err)
	}

	if m.view == ViewDetail && m.selectedVuln != nil {
		return m.renderDetailView()
	}

	if m.view == ViewChartsMenu {
		return m.renderChartsMenu()
	}

	if m.view == ViewExportMenu {
		return m.renderExportMenu()
	}

	if m.view == ViewVendorChart {
		return RenderVendorChartWithSelection(m.allVulns, m.width, m.height, m.selectedVendorIndex)
	}

	if m.view == ViewTimeline {
		return RenderTimelineChart(m.allVulns, m.width, m.height)
	}

	if m.view == ViewRansomware {
		return RenderRansomwareChart(m.allVulns, m.width, m.height)
	}

	if m.view == ViewCWE {
		return RenderCWEChart(m.allVulns, m.width, m.height)
	}

	if m.view == ViewRisk {
		return RenderRiskChart(m.allVulns, m.width, m.height)
	}

	return m.renderListView()
}

func (m Model) renderExportMenu() string {
	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("Export Report")
	b.WriteString("\n")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Current view info - use list's visible items which respects search filter
	currentCount := len(m.list.VisibleItems())
	totalCount := len(m.allVulns)
	infoStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	b.WriteString(infoStyle.Render(fmt.Sprintf("Current view: %d CVEs | Full catalog: %d CVEs", currentCount, totalCount)))
	b.WriteString("\n\n")

	// Menu options
	for i, opt := range m.exportOptions {
		if i == m.selectedExportIndex {
			// Highlighted
			selectedStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(PrimaryColor).
				Padding(0, 1)
			b.WriteString(selectedStyle.Render(fmt.Sprintf("> %s", opt.Name)))
		} else {
			b.WriteString(fmt.Sprintf("  %s", opt.Name))
		}
		b.WriteString("\n")
	}

	// Footer
	b.WriteString("\n")
	footerStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	b.WriteString(footerStyle.Render("j/k navigate • enter export • x/esc back"))

	return b.String()
}

func (m Model) renderChartsMenu() string {
	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("Charts & Graphs")
	b.WriteString("\n")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Menu options
	for i, opt := range m.chartOptions {
		if i == m.selectedChartIndex {
			// Highlighted
			selectedStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(PrimaryColor).
				Padding(0, 1)
			b.WriteString(selectedStyle.Render(fmt.Sprintf("> %s", opt.Name)))
		} else {
			b.WriteString(fmt.Sprintf("  %s", opt.Name))
		}
		b.WriteString("\n")
		descStyle := lipgloss.NewStyle().Foreground(SubtleColor)
		b.WriteString(descStyle.Render(fmt.Sprintf("    %s", opt.Description)))
		b.WriteString("\n\n")
	}

	// Footer
	footerStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	b.WriteString(footerStyle.Render("j/k navigate • enter select • g/esc back"))

	return b.String()
}

func (m Model) renderListView() string {
	var b strings.Builder

	// Stats header
	stats := fmt.Sprintf("%s %d KEVs | %s %d Ransomware | %s %d Overdue",
		StatHighlight.Render(""),
		m.stats.Total,
		lipgloss.NewStyle().Foreground(RansomwareColor).Render(""),
		m.stats.Ransomware,
		lipgloss.NewStyle().Foreground(OverdueColor).Render(""),
		m.stats.Overdue,
	)
	if m.loadingEPSS {
		stats += fmt.Sprintf(" | %s Loading EPSS...", m.spinner.View())
	}
	b.WriteString(StatsStyle.Render(stats))
	b.WriteString("\n")

	// Sort/filter indicator
	indicators := []string{fmt.Sprintf("Sort: %s", m.sortMode.String())}
	switch m.filterMode {
	case FilterRansomware:
		indicators = append(indicators, lipgloss.NewStyle().Foreground(RansomwareColor).Render("Filter: Ransomware"))
	case FilterOverdue:
		indicators = append(indicators, lipgloss.NewStyle().Foreground(OverdueColor).Render("Filter: Overdue"))
	case FilterVendor:
		indicators = append(indicators, lipgloss.NewStyle().Foreground(PrimaryColor).Render(fmt.Sprintf("Filter: %s", m.selectedVendorName)))
	}
	b.WriteString(SubtitleStyle.Render(strings.Join(indicators, " | ")))
	b.WriteString("\n")

	// List
	b.WriteString(m.list.View())

	// Status message or help
	if m.statusMsg != "" {
		b.WriteString("\n")
		b.WriteString(SubtitleStyle.Render(m.statusMsg))
	}

	// Help footer
	b.WriteString("\n")
	if m.showHelp {
		b.WriteString(m.help.View(m.keys))
	} else {
		helpText := "/ filter • s sort • r ransomware • d overdue • g graphs • x export • t top • b bottom • q quit"
		b.WriteString(SubtitleStyle.Render(helpText))
	}

	return b.String()
}

func (m Model) renderDetailView() string {
	var b strings.Builder

	// Header
	b.WriteString("\n")
	b.WriteString(CVEBadge.Render(m.selectedVuln.CVEID))
	if m.selectedVuln.RansomwareUse {
		b.WriteString("  ")
		b.WriteString(RansomwareBadge.Render("RANSOMWARE"))
	}
	if m.selectedVuln.IsOverdue() {
		b.WriteString("  ")
		b.WriteString(OverdueBadge.Render("OVERDUE"))
	}
	b.WriteString("\n\n")

	// Viewport with scrollable content
	if m.viewportReady {
		b.WriteString(m.viewport.View())
	}

	// Footer
	b.WriteString("\n")
	footer := "↑/↓ scroll | o open NVD | w open CWE | c copy | q/esc back"
	if m.statusMsg != "" {
		footer = m.statusMsg + " | " + footer
	}
	b.WriteString(SubtitleStyle.Render(footer))
	b.WriteString("\n")

	return b.String()
}

func (m Model) renderDetailContent() string {
	v := m.selectedVuln
	var b strings.Builder

	// Title
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Render(v.VulnerabilityName))
	b.WriteString("\n\n")

	// Fields
	fields := []struct {
		label string
		value string
	}{
		{"Vendor", v.VendorProject},
		{"Product", v.Product},
		{"Date Added", v.DateAdded.Format("2006-01-02")},
		{"Due Date", v.DueDate.Format("2006-01-02")},
		{"Status", v.DueDateStatus()},
		{"NVD URL", v.NVDURL()},
	}

	for _, f := range fields {
		if f.value != "" && f.value != "0001-01-01" {
			b.WriteString(LabelStyle.Render(f.label + ":"))
			if strings.HasPrefix(f.value, "http") {
				b.WriteString(URLStyle.Render(f.value))
			} else if f.label == "Status" && v.IsOverdue() {
				b.WriteString(lipgloss.NewStyle().Foreground(OverdueColor).Bold(true).Render(f.value))
			} else {
				b.WriteString(ValueStyle.Render(f.value))
			}
			b.WriteString("\n")
		}
	}

	// EPSS
	if v.EPSS.Score > 0 {
		b.WriteString("\n")
		b.WriteString(LabelStyle.Render("EPSS Score:"))
		b.WriteString(EPSSBadge(v.EPSS.Score))
		b.WriteString(" ")
		b.WriteString(EPSSBar(v.EPSS.Score, 20))
		b.WriteString("\n")
		b.WriteString(LabelStyle.Render("EPSS Percentile:"))
		b.WriteString(ValueStyle.Render(v.EPSSPercentileStr()))
		b.WriteString("\n")
	}

	// CVSS
	b.WriteString("\n")
	if m.loadingCVSS {
		b.WriteString(LabelStyle.Render("CVSS:"))
		b.WriteString(m.spinner.View())
		b.WriteString(" Loading...")
		b.WriteString("\n")
	} else if m.selectedCVSS != nil && (m.selectedCVSS.Primary != nil || len(m.selectedCVSS.Secondary) > 0) {
		// Primary (NVD) score
		if m.selectedCVSS.Primary != nil {
			p := m.selectedCVSS.Primary
			b.WriteString(LabelStyle.Render("NVD Base Score:"))
			b.WriteString(CVSSBadge(p.Score, p.Severity))
			b.WriteString("\n")
			b.WriteString(LabelStyle.Render("  Source:"))
			b.WriteString(ValueStyle.Render(p.Source))
			b.WriteString("\n")
			b.WriteString(LabelStyle.Render("  Vector:"))
			b.WriteString(SubtitleStyle.Render(p.Vector))
			b.WriteString("\n")
		}

		// Secondary (CNA/Vendor) scores
		for _, s := range m.selectedCVSS.Secondary {
			b.WriteString("\n")
			b.WriteString(LabelStyle.Render("CNA Base Score:"))
			b.WriteString(CVSSBadge(s.Score, s.Severity))
			b.WriteString("\n")
			b.WriteString(LabelStyle.Render("  Source:"))
			b.WriteString(ValueStyle.Render(s.Source))
			b.WriteString("\n")
			b.WriteString(LabelStyle.Render("  Vector:"))
			b.WriteString(SubtitleStyle.Render(s.Vector))
			b.WriteString("\n")
		}
	} else {
		b.WriteString(LabelStyle.Render("CVSS:"))
		b.WriteString(SubtitleStyle.Render("Not available"))
		b.WriteString("\n")
	}

	// Ransomware status
	b.WriteString(LabelStyle.Render("Ransomware Use:"))
	b.WriteString(RansomwareBadgeText(v.RansomwareUse))
	b.WriteString("\n")

	// CWEs
	if len(v.CWEs) > 0 {
		b.WriteString("\n")
		b.WriteString(LabelStyle.Render("CWEs:"))
		b.WriteString(CWEStyle.Render(strings.Join(v.CWEs, ", ")))
		b.WriteString(" ")
		b.WriteString(SubtitleStyle.Render("(w to open)"))
		b.WriteString("\n")
	}

	// Description
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(PrimaryColor).Render("Description"))
	b.WriteString("\n")
	b.WriteString(DescriptionStyle.Render(v.ShortDescription))
	b.WriteString("\n")

	// Required Action
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(PrimaryColor).Render("Required Action"))
	b.WriteString("\n")
	b.WriteString(DescriptionStyle.Render(v.RequiredAction))
	b.WriteString("\n")

	// Notes
	if v.Notes != "" {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(PrimaryColor).Render("Notes"))
		b.WriteString("\n")
		b.WriteString(DescriptionStyle.Render(v.Notes))
		b.WriteString("\n")
	}

	return b.String()
}

// Helper functions
func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}
	_ = cmd.Start()
}

func copyToClipboard(text string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case "windows":
		cmd = exec.Command("clip")
	default:
		return
	}
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}

// extractCWENumber extracts the numeric ID from a CWE string like "CWE-611"
func extractCWENumber(cwe string) string {
	cwe = strings.TrimSpace(cwe)
	if strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
		return cwe[4:]
	}
	// Already just a number
	if _, err := fmt.Sscanf(cwe, "%d", new(int)); err == nil {
		return cwe
	}
	return ""
}
