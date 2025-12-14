package tui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

// ExportFormat represents the export file format
type ExportFormat int

const (
	ExportJSON ExportFormat = iota
	ExportCSV
	ExportMarkdown
)

func (f ExportFormat) String() string {
	switch f {
	case ExportJSON:
		return "JSON"
	case ExportCSV:
		return "CSV"
	case ExportMarkdown:
		return "Markdown"
	}
	return ""
}

func (f ExportFormat) Extension() string {
	switch f {
	case ExportJSON:
		return ".json"
	case ExportCSV:
		return ".csv"
	case ExportMarkdown:
		return ".md"
	}
	return ""
}

// ExportScope represents what data to export
type ExportScope int

const (
	ExportCurrentView ExportScope = iota
	ExportFullCatalog
)

func (s ExportScope) String() string {
	switch s {
	case ExportCurrentView:
		return "Current View"
	case ExportFullCatalog:
		return "Full Catalog"
	}
	return ""
}

// ExportOption represents a menu option
type ExportOption struct {
	Name   string
	Format ExportFormat
	Scope  ExportScope
}

// ExportResult contains the result of an export operation
type ExportResult struct {
	FilePath string
	Count    int
	Err      error
}

// Export exports vulnerabilities to a file
func Export(vulns []model.Vulnerability, format ExportFormat, outputDir string) ExportResult {
	timestamp := time.Now().Format("2006-01-02_150405")
	filename := fmt.Sprintf("kev_report_%s%s", timestamp, format.Extension())
	filepath := filepath.Join(outputDir, filename)

	var err error
	switch format {
	case ExportJSON:
		err = exportJSON(vulns, filepath)
	case ExportCSV:
		err = exportCSV(vulns, filepath)
	case ExportMarkdown:
		err = exportMarkdown(vulns, filepath)
	}

	if err != nil {
		return ExportResult{Err: err}
	}

	return ExportResult{FilePath: filepath, Count: len(vulns)}
}

func exportJSON(vulns []model.Vulnerability, filepath string) error {
	type ExportVuln struct {
		CVEID             string   `json:"cve_id"`
		VendorProject     string   `json:"vendor"`
		Product           string   `json:"product"`
		VulnerabilityName string   `json:"name"`
		DateAdded         string   `json:"date_added"`
		DueDate           string   `json:"due_date"`
		ShortDescription  string   `json:"description"`
		RequiredAction    string   `json:"required_action"`
		RansomwareUse     bool     `json:"ransomware_use"`
		Notes             string   `json:"notes,omitempty"`
		CWEs              []string `json:"cwes,omitempty"`
		EPSSScore         float64  `json:"epss_score,omitempty"`
		EPSSPercentile    float64  `json:"epss_percentile,omitempty"`
		NVDURL            string   `json:"nvd_url"`
		IsOverdue         bool     `json:"is_overdue"`
	}

	export := struct {
		ExportedAt      string       `json:"exported_at"`
		TotalCount      int          `json:"total_count"`
		Vulnerabilities []ExportVuln `json:"vulnerabilities"`
	}{
		ExportedAt: time.Now().Format(time.RFC3339),
		TotalCount: len(vulns),
	}

	for _, v := range vulns {
		export.Vulnerabilities = append(export.Vulnerabilities, ExportVuln{
			CVEID:             v.CVEID,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         v.DateAdded.Format("2006-01-02"),
			DueDate:           v.DueDate.Format("2006-01-02"),
			ShortDescription:  v.ShortDescription,
			RequiredAction:    v.RequiredAction,
			RansomwareUse:     v.RansomwareUse,
			Notes:             v.Notes,
			CWEs:              v.CWEs,
			EPSSScore:         v.EPSS.Score,
			EPSSPercentile:    v.EPSS.Percentile,
			NVDURL:            v.NVDURL(),
			IsOverdue:         v.IsOverdue(),
		})
	}

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(export)
}

func exportCSV(vulns []model.Vulnerability, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	header := []string{
		"CVE ID", "Vendor", "Product", "Name", "Date Added", "Due Date",
		"Description", "Required Action", "Ransomware Use", "CWEs",
		"EPSS Score", "EPSS Percentile", "NVD URL", "Overdue",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Data rows
	for _, v := range vulns {
		ransomware := "No"
		if v.RansomwareUse {
			ransomware = "Yes"
		}
		overdue := "No"
		if v.IsOverdue() {
			overdue = "Yes"
		}

		row := []string{
			v.CVEID,
			v.VendorProject,
			v.Product,
			v.VulnerabilityName,
			v.DateAdded.Format("2006-01-02"),
			v.DueDate.Format("2006-01-02"),
			v.ShortDescription,
			v.RequiredAction,
			ransomware,
			strings.Join(v.CWEs, "; "),
			fmt.Sprintf("%.4f", v.EPSS.Score),
			fmt.Sprintf("%.4f", v.EPSS.Percentile),
			v.NVDURL(),
			overdue,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func exportMarkdown(vulns []model.Vulnerability, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	var b strings.Builder

	// Header
	b.WriteString("# CISA Known Exploited Vulnerabilities Report\n\n")
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**Total CVEs:** %d\n\n", len(vulns)))

	// Summary stats
	ransomwareCount := 0
	overdueCount := 0
	for _, v := range vulns {
		if v.RansomwareUse {
			ransomwareCount++
		}
		if v.IsOverdue() {
			overdueCount++
		}
	}
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Ransomware Associated:** %d (%.1f%%)\n", ransomwareCount, float64(ransomwareCount)/float64(len(vulns))*100))
	b.WriteString(fmt.Sprintf("- **Overdue:** %d (%.1f%%)\n\n", overdueCount, float64(overdueCount)/float64(len(vulns))*100))

	// Table
	b.WriteString("## Vulnerabilities\n\n")
	b.WriteString("| CVE ID | Vendor | Product | Due Date | Ransomware | EPSS |\n")
	b.WriteString("|--------|--------|---------|----------|------------|------|\n")

	for _, v := range vulns {
		ransomware := ""
		if v.RansomwareUse {
			ransomware = "Yes"
		}
		epss := ""
		if v.EPSS.Score > 0 {
			epss = fmt.Sprintf("%.1f%%", v.EPSS.Score*100)
		}
		dueDate := v.DueDate.Format("2006-01-02")
		if v.IsOverdue() {
			dueDate = fmt.Sprintf("**%s** (OVERDUE)", dueDate)
		}

		b.WriteString(fmt.Sprintf("| [%s](%s) | %s | %s | %s | %s | %s |\n",
			v.CVEID, v.NVDURL(), v.VendorProject, v.Product, dueDate, ransomware, epss))
	}

	b.WriteString("\n---\n\n")
	b.WriteString("*Generated by kevs-tui*\n")

	_, err = file.WriteString(b.String())
	return err
}
