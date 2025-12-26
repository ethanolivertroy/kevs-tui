package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

func TestExtractCWENumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard CWE", "CWE-611", "611"},
		{"lowercase cwe", "cwe-123", "123"},
		{"four digit CWE", "CWE-1234", "1234"},
		{"plain number", "611", "611"},
		{"plain number large", "1234", "1234"},
		{"empty string", "", ""},
		{"invalid format", "invalid", ""},
		{"partial CWE", "CWE-", ""},
		{"spaces around", "  CWE-611  ", "611"},
		{"mixed case", "CwE-789", "789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractCWENumber(tt.input); got != tt.expected {
				t.Errorf("extractCWENumber(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// Export confirmation tests

func TestPendingExport(t *testing.T) {
	vulns := []model.Vulnerability{
		{CVEID: "CVE-2024-0001"},
		{CVEID: "CVE-2024-0002"},
	}

	pending := &PendingExport{
		Vulns:  vulns,
		Format: ExportJSON,
		Count:  len(vulns),
	}

	if pending.Count != 2 {
		t.Errorf("Count = %d, want 2", pending.Count)
	}
	if pending.Format != ExportJSON {
		t.Errorf("Format = %v, want ExportJSON", pending.Format)
	}
}

func TestPendingExportFormats(t *testing.T) {
	tests := []struct {
		name   string
		format ExportFormat
	}{
		{"JSON format", ExportJSON},
		{"CSV format", ExportCSV},
		{"Markdown format", ExportMarkdown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pending := &PendingExport{
				Vulns:  []model.Vulnerability{{CVEID: "CVE-2024-0001"}},
				Format: tt.format,
				Count:  1,
			}
			if pending.Format != tt.format {
				t.Errorf("Format = %v, want %v", pending.Format, tt.format)
			}
		})
	}
}

func TestRenderExportConfirm(t *testing.T) {
	m := NewModel()
	m.width = 80
	m.height = 24
	m.pendingExport = &PendingExport{
		Vulns:  []model.Vulnerability{{CVEID: "CVE-2024-0001"}},
		Format: ExportJSON,
		Count:  1,
	}

	output := m.renderExportConfirm()

	if output == "" {
		t.Error("renderExportConfirm returned empty string")
	}
	if !strings.Contains(output, "Confirm Export") {
		t.Error("Missing 'Confirm Export' title")
	}
	if !strings.Contains(output, "1 CVE") {
		t.Error("Missing CVE count")
	}
}

func TestRenderExportConfirmMultiple(t *testing.T) {
	m := NewModel()
	m.width = 80
	m.height = 24
	m.pendingExport = &PendingExport{
		Vulns: []model.Vulnerability{
			{CVEID: "CVE-2024-0001"},
			{CVEID: "CVE-2024-0002"},
			{CVEID: "CVE-2024-0003"},
		},
		Format: ExportCSV,
		Count:  3,
	}

	output := m.renderExportConfirm()

	if !strings.Contains(output, "3 CVE") {
		t.Error("Missing correct CVE count for multiple items")
	}
}

// Detail view table tests

func TestRenderDetailContentWithTable(t *testing.T) {
	m := NewModel()
	m.width = 80
	m.selectedVuln = &model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2024-1234",
			VendorProject:     "Microsoft",
			Product:           "Windows",
			VulnerabilityName: "Test Vulnerability",
			DateAdded:         time.Now(),
			DueDate:           time.Now().Add(24 * time.Hour),
		},
	}

	output := m.renderDetailContent()

	// Check table is rendered (has rounded border characters)
	if !strings.Contains(output, "╭") || !strings.Contains(output, "╮") {
		t.Error("Missing rounded border characters - table may not be rendering")
	}
	if !strings.Contains(output, "Microsoft") {
		t.Error("Missing vendor in output")
	}
	if !strings.Contains(output, "Windows") {
		t.Error("Missing product in output")
	}
}

func TestRenderDetailContentFields(t *testing.T) {
	m := NewModel()
	m.width = 100
	m.selectedVuln = &model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2024-5678",
			VendorProject:     "Apache",
			Product:           "Struts",
			VulnerabilityName: "Remote Code Execution",
			ShortDescription:  "A critical RCE vulnerability",
			RequiredAction:    "Apply updates per vendor instructions",
			RansomwareUse:     true,
			DateAdded:         time.Now().Add(-48 * time.Hour),
			DueDate:           time.Now().Add(24 * time.Hour),
		},
	}

	output := m.renderDetailContent()

	// Check CVE ID is present
	if !strings.Contains(output, "CVE-2024-5678") {
		t.Error("Missing CVE ID in output")
	}
	// Check vendor
	if !strings.Contains(output, "Apache") {
		t.Error("Missing vendor in output")
	}
	// Check product
	if !strings.Contains(output, "Struts") {
		t.Error("Missing product in output")
	}
}

func TestRenderDetailContentNilVuln(t *testing.T) {
	m := NewModel()
	m.width = 80
	m.selectedVuln = nil

	output := m.renderDetailContent()

	// Should handle nil gracefully
	if output != "No vulnerability selected" {
		t.Errorf("Expected 'No vulnerability selected', got %q", output)
	}
}

// CVE context message tests

func TestExitDetailViewSendsCVESelectedMsgNil(t *testing.T) {
	m := NewModel()
	m.width = 80
	m.height = 24
	m.loading = false
	m.view = ViewDetail

	// Set a selected vulnerability
	testVuln := &model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2025-88888",
			VendorProject:     "ExitTestVendor",
			Product:           "ExitTestProduct",
			VulnerabilityName: "Exit Test Vulnerability",
		},
	}
	m.selectedVuln = testVuln

	// Simulate pressing escape to exit detail view
	msg := tea.KeyMsg{Type: tea.KeyEscape}
	newModel, cmd := m.Update(msg)

	updatedModel := newModel.(Model)

	// Verify we're back in list view
	if updatedModel.view != ViewList {
		t.Errorf("Expected ViewList, got %v", updatedModel.view)
	}

	// Verify selectedVuln is cleared
	if updatedModel.selectedVuln != nil {
		t.Error("Expected selectedVuln to be nil after exiting detail view")
	}

	// Execute the command to get the CVESelectedMsg
	if cmd == nil {
		t.Fatal("Expected non-nil command from exiting detail view")
	}

	// Execute the command function to get the message
	resultMsg := cmd()

	// Check if it's a CVESelectedMsg with nil CVE
	cveMsg, ok := resultMsg.(model.CVESelectedMsg)
	if !ok {
		t.Fatalf("Expected CVESelectedMsg, got %T", resultMsg)
	}
	if cveMsg.CVE != nil {
		t.Errorf("Expected nil CVE in message, got %+v", cveMsg.CVE)
	}
}
