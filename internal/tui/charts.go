package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/barchart"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

// VendorStats holds vendor breakdown data
type VendorStats struct {
	Name  string
	Count int
}

// MonthStats holds monthly CVE counts
type MonthStats struct {
	Month time.Time
	Count int
}

// GetTopVendors returns the top N vendors by CVE count
func GetTopVendors(vulns []model.Vulnerability, n int) []VendorStats {
	vendorCounts := make(map[string]int)
	for _, v := range vulns {
		vendorCounts[v.VendorProject]++
	}

	var stats []VendorStats
	for vendor, count := range vendorCounts {
		stats = append(stats, VendorStats{Name: vendor, Count: count})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	if len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// GetMonthlyStats returns CVE counts grouped by month
func GetMonthlyStats(vulns []model.Vulnerability, months int) []MonthStats {
	monthCounts := make(map[string]int)

	// Count CVEs per month
	for _, v := range vulns {
		if v.DateAdded.IsZero() {
			continue
		}
		key := v.DateAdded.Format("2006-01")
		monthCounts[key]++
	}

	// Get last N months
	now := time.Now()
	var stats []MonthStats
	for i := months - 1; i >= 0; i-- {
		m := now.AddDate(0, -i, 0)
		key := m.Format("2006-01")
		count := monthCounts[key]
		stats = append(stats, MonthStats{
			Month: time.Date(m.Year(), m.Month(), 1, 0, 0, 0, 0, time.UTC),
			Count: count,
		})
	}

	return stats
}

// RenderVendorChart renders a horizontal bar chart of top vendors
func RenderVendorChart(vulns []model.Vulnerability, width, height int) string {
	return RenderVendorChartWithSelection(vulns, width, height, -1)
}

// RenderVendorChartWithSelection renders a vendor chart with optional selection highlight
func RenderVendorChartWithSelection(vulns []model.Vulnerability, width, height int, selectedIndex int) string {
	vendors := GetTopVendors(vulns, 10)
	if len(vendors) == 0 {
		return "No vendor data available"
	}

	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("Top 10 Vendors by CVE Count")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Create bar chart
	bc := barchart.New(width-4, height-8,
		barchart.WithNoAutoBarWidth(),
		barchart.WithBarWidth(3),
		barchart.WithBarGap(1),
	)

	// Add bars with color gradient
	colors := []lipgloss.Color{
		lipgloss.Color("#9B0000"), // Critical red
		lipgloss.Color("#FF5F56"), // High red
		lipgloss.Color("#FF8C00"), // Orange
		lipgloss.Color("#FFCC00"), // Yellow
		lipgloss.Color("#04B575"), // Green
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
	}

	var items []barchart.BarData
	for i, v := range vendors {
		color := colors[i%len(colors)]
		items = append(items, barchart.BarData{
			Label: truncateString(v.Name, 12),
			Values: []barchart.BarValue{{
				Name:  v.Name,
				Value: float64(v.Count),
				Style: lipgloss.NewStyle().Foreground(color),
			}},
		})
	}
	bc.PushAll(items)
	bc.Draw()

	b.WriteString(bc.View())
	b.WriteString("\n\n")

	// Legend with full names and selection highlight
	for i, v := range vendors {
		color := colors[i%len(colors)]
		marker := lipgloss.NewStyle().Foreground(color).Render("█")

		if i == selectedIndex {
			// Highlight selected vendor
			selectedStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(PrimaryColor)
			b.WriteString(fmt.Sprintf("%s %s\n", marker, selectedStyle.Render(fmt.Sprintf(" %s: %d ", v.Name, v.Count))))
		} else {
			b.WriteString(fmt.Sprintf("%s %s: %d\n", marker, v.Name, v.Count))
		}
	}

	// Footer
	b.WriteString("\n")
	footerStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	footer := "j/k navigate • enter filter by vendor • g/esc back"
	b.WriteString(footerStyle.Render(footer))

	return b.String()
}

// RenderTimelineChart renders a bar chart of CVEs over time
func RenderTimelineChart(vulns []model.Vulnerability, width, height int) string {
	stats := GetMonthlyStats(vulns, 12)
	if len(stats) == 0 {
		return "No timeline data available"
	}

	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("CVEs Added Over Last 12 Months")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Create bar chart
	bc := barchart.New(width-4, height-10,
		barchart.WithNoAutoBarWidth(),
		barchart.WithBarWidth(4),
		barchart.WithBarGap(1),
	)

	// Find max for color scaling
	maxCount := 0
	for _, s := range stats {
		if s.Count > maxCount {
			maxCount = s.Count
		}
	}

	var items []barchart.BarData
	for _, s := range stats {
		// Color based on count intensity
		var color lipgloss.Color
		if maxCount > 0 {
			intensity := float64(s.Count) / float64(maxCount)
			if intensity > 0.7 {
				color = lipgloss.Color("#FF5F56") // High - red
			} else if intensity > 0.4 {
				color = lipgloss.Color("#FFCC00") // Medium - yellow
			} else {
				color = lipgloss.Color("#04B575") // Low - green
			}
		} else {
			color = SubtleColor
		}

		items = append(items, barchart.BarData{
			Label: s.Month.Format("Jan"),
			Values: []barchart.BarValue{{
				Name:  s.Month.Format("2006-01"),
				Value: float64(s.Count),
				Style: lipgloss.NewStyle().Foreground(color),
			}},
		})
	}
	bc.PushAll(items)
	bc.Draw()

	b.WriteString(bc.View())
	b.WriteString("\n\n")

	// Summary stats
	total := 0
	for _, s := range stats {
		total += s.Count
	}
	avg := float64(total) / float64(len(stats))

	summaryStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	b.WriteString(summaryStyle.Render(fmt.Sprintf("Total: %d CVEs | Average: %.1f per month", total, avg)))
	b.WriteString("\n\n")

	// Footer
	footer := summaryStyle.Render("g/esc back to charts menu")
	b.WriteString(footer)

	return b.String()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "."
}

// RansomwareStats holds ransomware usage breakdown
type RansomwareStats struct {
	Known   int
	Unknown int
	Total   int
}

// CWEStats holds CWE occurrence data
type CWEStats struct {
	ID    string
	Count int
}

// RiskStats holds EPSS-based risk breakdown
type RiskStats struct {
	Critical int // EPSS >= 0.7
	High     int // EPSS >= 0.4
	Medium   int // EPSS >= 0.1
	Low      int // EPSS < 0.1
}

// GetRansomwareStats returns ransomware usage breakdown
func GetRansomwareStats(vulns []model.Vulnerability) RansomwareStats {
	stats := RansomwareStats{Total: len(vulns)}
	for _, v := range vulns {
		if v.RansomwareUse {
			stats.Known++
		} else {
			stats.Unknown++
		}
	}
	return stats
}

// GetTopCWEs returns the top N CWEs by occurrence
func GetTopCWEs(vulns []model.Vulnerability, n int) []CWEStats {
	cweCounts := make(map[string]int)
	for _, v := range vulns {
		for _, cwe := range v.CWEs {
			cweCounts[cwe]++
		}
	}

	var stats []CWEStats
	for cwe, count := range cweCounts {
		stats = append(stats, CWEStats{ID: cwe, Count: count})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	if len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// GetRiskStats returns EPSS-based risk breakdown
func GetRiskStats(vulns []model.Vulnerability) RiskStats {
	var stats RiskStats
	for _, v := range vulns {
		score := v.EPSS.Score
		switch {
		case score >= 0.7:
			stats.Critical++
		case score >= 0.4:
			stats.High++
		case score >= 0.1:
			stats.Medium++
		default:
			stats.Low++
		}
	}
	return stats
}

// RenderRansomwareChart renders a chart showing ransomware usage breakdown
func RenderRansomwareChart(vulns []model.Vulnerability, width, height int) string {
	stats := GetRansomwareStats(vulns)
	if stats.Total == 0 {
		return "No data available"
	}

	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("Ransomware Campaign Usage")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Create bar chart
	bc := barchart.New(width-4, height-12,
		barchart.WithNoAutoBarWidth(),
		barchart.WithBarWidth(8),
		barchart.WithBarGap(2),
	)

	items := []barchart.BarData{
		{
			Label: "Known",
			Values: []barchart.BarValue{{
				Name:  "Known",
				Value: float64(stats.Known),
				Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F56")),
			}},
		},
		{
			Label: "Unknown",
			Values: []barchart.BarValue{{
				Name:  "Unknown",
				Value: float64(stats.Unknown),
				Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")),
			}},
		},
	}
	bc.PushAll(items)
	bc.Draw()

	b.WriteString(bc.View())
	b.WriteString("\n\n")

	// Summary
	knownPct := float64(stats.Known) / float64(stats.Total) * 100
	unknownPct := float64(stats.Unknown) / float64(stats.Total) * 100

	summaryStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	knownStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F56")).Bold(true)
	unknownStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)

	b.WriteString(knownStyle.Render(fmt.Sprintf("Known: %d (%.1f%%)", stats.Known, knownPct)))
	b.WriteString("  ")
	b.WriteString(unknownStyle.Render(fmt.Sprintf("Unknown: %d (%.1f%%)", stats.Unknown, unknownPct)))
	b.WriteString("\n\n")

	b.WriteString(summaryStyle.Render(fmt.Sprintf("Total CVEs analyzed: %d", stats.Total)))
	b.WriteString("\n\n")

	// Footer
	footer := summaryStyle.Render("g/esc back to charts menu")
	b.WriteString(footer)

	return b.String()
}

// RenderCWEChart renders a chart showing top CWEs
func RenderCWEChart(vulns []model.Vulnerability, width, height int) string {
	cwes := GetTopCWEs(vulns, 10)
	if len(cwes) == 0 {
		return "No CWE data available"
	}

	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("Top 10 CWE Types")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Create bar chart
	bc := barchart.New(width-4, height-10,
		barchart.WithNoAutoBarWidth(),
		barchart.WithBarWidth(3),
		barchart.WithBarGap(1),
	)

	// Colors for CWE bars
	colors := []lipgloss.Color{
		lipgloss.Color("#9B0000"),
		lipgloss.Color("#FF5F56"),
		lipgloss.Color("#FF8C00"),
		lipgloss.Color("#FFCC00"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
		lipgloss.Color("#04B575"),
	}

	var items []barchart.BarData
	for i, c := range cwes {
		color := colors[i%len(colors)]
		items = append(items, barchart.BarData{
			Label: truncateString(c.ID, 10),
			Values: []barchart.BarValue{{
				Name:  c.ID,
				Value: float64(c.Count),
				Style: lipgloss.NewStyle().Foreground(color),
			}},
		})
	}
	bc.PushAll(items)
	bc.Draw()

	b.WriteString(bc.View())
	b.WriteString("\n\n")

	// Legend with CWE IDs
	for i, c := range cwes {
		color := colors[i%len(colors)]
		marker := lipgloss.NewStyle().Foreground(color).Render("█")
		b.WriteString(fmt.Sprintf("%s %s: %d\n", marker, c.ID, c.Count))
	}

	// Footer
	b.WriteString("\n")
	footerStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	footer := "g/esc back to charts menu"
	b.WriteString(footerStyle.Render(footer))

	return b.String()
}

// RenderRiskChart renders a chart showing EPSS-based risk distribution
func RenderRiskChart(vulns []model.Vulnerability, width, height int) string {
	stats := GetRiskStats(vulns)
	total := stats.Critical + stats.High + stats.Medium + stats.Low
	if total == 0 {
		return "No EPSS data available"
	}

	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(PrimaryColor).
		Padding(0, 1).
		Render("Risk Distribution (EPSS-based)")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Create bar chart
	bc := barchart.New(width-4, height-14,
		barchart.WithNoAutoBarWidth(),
		barchart.WithBarWidth(6),
		barchart.WithBarGap(2),
	)

	items := []barchart.BarData{
		{
			Label: "Critical",
			Values: []barchart.BarValue{{
				Name:  "Critical",
				Value: float64(stats.Critical),
				Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#9B0000")),
			}},
		},
		{
			Label: "High",
			Values: []barchart.BarValue{{
				Name:  "High",
				Value: float64(stats.High),
				Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F56")),
			}},
		},
		{
			Label: "Medium",
			Values: []barchart.BarValue{{
				Name:  "Medium",
				Value: float64(stats.Medium),
				Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00")),
			}},
		},
		{
			Label: "Low",
			Values: []barchart.BarValue{{
				Name:  "Low",
				Value: float64(stats.Low),
				Style: lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")),
			}},
		},
	}
	bc.PushAll(items)
	bc.Draw()

	b.WriteString(bc.View())
	b.WriteString("\n\n")

	// Summary with percentages
	critPct := float64(stats.Critical) / float64(total) * 100
	highPct := float64(stats.High) / float64(total) * 100
	medPct := float64(stats.Medium) / float64(total) * 100
	lowPct := float64(stats.Low) / float64(total) * 100

	critStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#9B0000")).Bold(true)
	highStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F56")).Bold(true)
	medStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00")).Bold(true)
	lowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)

	b.WriteString(critStyle.Render(fmt.Sprintf("Critical (≥70%%): %d (%.1f%%)", stats.Critical, critPct)))
	b.WriteString("\n")
	b.WriteString(highStyle.Render(fmt.Sprintf("High (≥40%%):     %d (%.1f%%)", stats.High, highPct)))
	b.WriteString("\n")
	b.WriteString(medStyle.Render(fmt.Sprintf("Medium (≥10%%):   %d (%.1f%%)", stats.Medium, medPct)))
	b.WriteString("\n")
	b.WriteString(lowStyle.Render(fmt.Sprintf("Low (<10%%):      %d (%.1f%%)", stats.Low, lowPct)))
	b.WriteString("\n\n")

	// Footer
	footerStyle := lipgloss.NewStyle().Foreground(SubtleColor)
	b.WriteString(footerStyle.Render("EPSS = Exploit Prediction Scoring System (probability of exploitation)"))
	b.WriteString("\n")
	footer := footerStyle.Render("g/esc back to charts menu")
	b.WriteString(footer)

	return b.String()
}
