package tui

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

func testVuln(cveID string, ransomware bool, epss float64) model.Vulnerability {
	return model.Vulnerability{
		CVEID:             cveID,
		VendorProject:     "TestVendor",
		Product:           "TestProduct",
		VulnerabilityName: "Test Vulnerability",
		DateAdded:         time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
		DueDate:           time.Date(2024, 2, 15, 0, 0, 0, 0, time.UTC),
		ShortDescription:  "Test description",
		RequiredAction:    "Apply updates",
		RansomwareUse:     ransomware,
		Notes:             "Test notes",
		CWEs:              []string{"CWE-79", "CWE-89"},
		EPSS: model.EPSSScore{
			Score:      epss,
			Percentile: epss * 100,
		},
	}
}

func TestExportFormatString(t *testing.T) {
	tests := []struct {
		format   ExportFormat
		expected string
	}{
		{ExportJSON, "JSON"},
		{ExportCSV, "CSV"},
		{ExportMarkdown, "Markdown"},
		{ExportFormat(99), ""}, // unknown format
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.format.String(); got != tt.expected {
				t.Errorf("ExportFormat.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExportFormatExtension(t *testing.T) {
	tests := []struct {
		format   ExportFormat
		expected string
	}{
		{ExportJSON, ".json"},
		{ExportCSV, ".csv"},
		{ExportMarkdown, ".md"},
		{ExportFormat(99), ""}, // unknown format
	}

	for _, tt := range tests {
		t.Run(tt.format.String(), func(t *testing.T) {
			if got := tt.format.Extension(); got != tt.expected {
				t.Errorf("ExportFormat.Extension() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExportScopeString(t *testing.T) {
	tests := []struct {
		scope    ExportScope
		expected string
	}{
		{ExportCurrentView, "Current View"},
		{ExportFullCatalog, "Full Catalog"},
		{ExportScope(99), ""}, // unknown scope
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.scope.String(); got != tt.expected {
				t.Errorf("ExportScope.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExport(t *testing.T) {
	vulns := []model.Vulnerability{
		testVuln("CVE-2024-0001", true, 0.5),
		testVuln("CVE-2024-0002", false, 0.3),
	}

	tests := []struct {
		name   string
		format ExportFormat
		ext    string
	}{
		{"JSON export", ExportJSON, ".json"},
		{"CSV export", ExportCSV, ".csv"},
		{"Markdown export", ExportMarkdown, ".md"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			result := Export(vulns, tt.format, tmpDir)

			if result.Err != nil {
				t.Fatalf("Export() error = %v", result.Err)
			}

			if result.Count != len(vulns) {
				t.Errorf("Export() count = %d, want %d", result.Count, len(vulns))
			}

			if !strings.HasPrefix(filepath.Base(result.FilePath), "kev_report_") {
				t.Errorf("Export() filename should start with 'kev_report_', got %s", filepath.Base(result.FilePath))
			}

			if !strings.HasSuffix(result.FilePath, tt.ext) {
				t.Errorf("Export() filename should end with %s, got %s", tt.ext, result.FilePath)
			}

			if _, err := os.Stat(result.FilePath); os.IsNotExist(err) {
				t.Errorf("Export() file was not created at %s", result.FilePath)
			}
		})
	}
}

func TestExportInvalidDir(t *testing.T) {
	vulns := []model.Vulnerability{testVuln("CVE-2024-0001", false, 0.1)}
	result := Export(vulns, ExportJSON, "/nonexistent/path/that/does/not/exist")

	if result.Err == nil {
		t.Error("Export() should return error for invalid directory")
	}
}

func TestExportJSON(t *testing.T) {
	vulns := []model.Vulnerability{
		testVuln("CVE-2024-0001", true, 0.75),
		testVuln("CVE-2024-0002", false, 0.25),
	}

	tmpDir := t.TempDir()
	result := Export(vulns, ExportJSON, tmpDir)

	if result.Err != nil {
		t.Fatalf("Export() error = %v", result.Err)
	}

	data, err := os.ReadFile(result.FilePath)
	if err != nil {
		t.Fatalf("Failed to read exported file: %v", err)
	}

	var export struct {
		ExportedAt      string `json:"exported_at"`
		TotalCount      int    `json:"total_count"`
		Vulnerabilities []struct {
			CVEID         string   `json:"cve_id"`
			Vendor        string   `json:"vendor"`
			Product       string   `json:"product"`
			RansomwareUse bool     `json:"ransomware_use"`
			CWEs          []string `json:"cwes"`
			EPSSScore     float64  `json:"epss_score"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if export.TotalCount != 2 {
		t.Errorf("JSON total_count = %d, want 2", export.TotalCount)
	}

	if len(export.Vulnerabilities) != 2 {
		t.Errorf("JSON vulnerabilities count = %d, want 2", len(export.Vulnerabilities))
	}

	if export.Vulnerabilities[0].CVEID != "CVE-2024-0001" {
		t.Errorf("JSON first CVE = %s, want CVE-2024-0001", export.Vulnerabilities[0].CVEID)
	}

	if !export.Vulnerabilities[0].RansomwareUse {
		t.Error("JSON first vuln should have ransomware_use = true")
	}

	if export.Vulnerabilities[0].EPSSScore != 0.75 {
		t.Errorf("JSON first vuln EPSS = %f, want 0.75", export.Vulnerabilities[0].EPSSScore)
	}
}

func TestExportCSV(t *testing.T) {
	vulns := []model.Vulnerability{
		testVuln("CVE-2024-0001", true, 0.5),
		testVuln("CVE-2024-0002", false, 0.3),
	}

	tmpDir := t.TempDir()
	result := Export(vulns, ExportCSV, tmpDir)

	if result.Err != nil {
		t.Fatalf("Export() error = %v", result.Err)
	}

	file, err := os.Open(result.FilePath)
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Header + 2 data rows
	if len(records) != 3 {
		t.Errorf("CSV row count = %d, want 3 (header + 2 vulns)", len(records))
	}

	// Check header
	expectedHeaders := []string{"CVE ID", "Vendor", "Product", "Name", "Date Added", "Due Date",
		"Description", "Required Action", "Ransomware Use", "CWEs", "EPSS Score", "EPSS Percentile", "NVD URL", "Overdue"}
	if len(records[0]) != len(expectedHeaders) {
		t.Errorf("CSV header column count = %d, want %d", len(records[0]), len(expectedHeaders))
	}

	for i, h := range expectedHeaders {
		if records[0][i] != h {
			t.Errorf("CSV header[%d] = %q, want %q", i, records[0][i], h)
		}
	}

	// Check first data row
	if records[1][0] != "CVE-2024-0001" {
		t.Errorf("CSV first row CVE = %s, want CVE-2024-0001", records[1][0])
	}

	if records[1][8] != "Yes" { // Ransomware Use
		t.Errorf("CSV first row Ransomware = %s, want Yes", records[1][8])
	}

	if records[2][8] != "No" { // Second row ransomware
		t.Errorf("CSV second row Ransomware = %s, want No", records[2][8])
	}
}

func TestExportMarkdown(t *testing.T) {
	vulns := []model.Vulnerability{
		testVuln("CVE-2024-0001", true, 0.5),
		testVuln("CVE-2024-0002", false, 0.3),
	}

	tmpDir := t.TempDir()
	result := Export(vulns, ExportMarkdown, tmpDir)

	if result.Err != nil {
		t.Fatalf("Export() error = %v", result.Err)
	}

	data, err := os.ReadFile(result.FilePath)
	if err != nil {
		t.Fatalf("Failed to read Markdown file: %v", err)
	}

	content := string(data)

	// Check title
	if !strings.Contains(content, "# CISA Known Exploited Vulnerabilities Report") {
		t.Error("Markdown missing title")
	}

	// Check total count
	if !strings.Contains(content, "**Total CVEs:** 2") {
		t.Error("Markdown missing or incorrect total count")
	}

	// Check summary section
	if !strings.Contains(content, "## Summary") {
		t.Error("Markdown missing Summary section")
	}

	if !strings.Contains(content, "Ransomware Associated") {
		t.Error("Markdown missing ransomware stats")
	}

	// Check table header
	if !strings.Contains(content, "| CVE ID | Vendor | Product | Due Date | Ransomware | EPSS |") {
		t.Error("Markdown missing table header")
	}

	// Check CVE entries
	if !strings.Contains(content, "CVE-2024-0001") {
		t.Error("Markdown missing CVE-2024-0001")
	}

	if !strings.Contains(content, "CVE-2024-0002") {
		t.Error("Markdown missing CVE-2024-0002")
	}

	// Check footer
	if !strings.Contains(content, "Generated by kevs-tui") {
		t.Error("Markdown missing footer")
	}
}

func TestExportEmptyList(t *testing.T) {
	var vulns []model.Vulnerability

	tmpDir := t.TempDir()

	tests := []struct {
		name   string
		format ExportFormat
	}{
		{"Empty JSON", ExportJSON},
		{"Empty CSV", ExportCSV},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Export(vulns, tt.format, tmpDir)

			if result.Err != nil {
				t.Fatalf("Export() error = %v", result.Err)
			}

			if result.Count != 0 {
				t.Errorf("Export() count = %d, want 0", result.Count)
			}
		})
	}
}
