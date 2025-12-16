package model

import (
	"strings"
	"testing"
	"time"
)

func TestVulnerabilityItemTitle(t *testing.T) {
	tests := []struct {
		name     string
		vulnName string
		expected string
	}{
		{"standard title", "Log4Shell Remote Code Execution", "Log4Shell Remote Code Execution"},
		{"empty title", "", ""},
		{"unicode title", "漏洞 Vulnerability", "漏洞 Vulnerability"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := VulnerabilityItem{
				Vulnerability: Vulnerability{VulnerabilityName: tt.vulnName},
			}
			if got := item.Title(); got != tt.expected {
				t.Errorf("Title() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestVulnerabilityItemDescription(t *testing.T) {
	date := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		vendor    string
		product   string
		dateAdded time.Time
		contains  []string
	}{
		{
			name:      "full description",
			vendor:    "Microsoft",
			product:   "Windows",
			dateAdded: date,
			contains:  []string{"Microsoft", "Windows", "2024-01-15"},
		},
		{
			name:      "zero date",
			vendor:    "Apple",
			product:   "macOS",
			dateAdded: time.Time{},
			contains:  []string{"Apple", "macOS", "Added:"},
		},
		{
			name:      "empty fields",
			vendor:    "",
			product:   "",
			dateAdded: time.Time{},
			contains:  []string{"|"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := VulnerabilityItem{
				Vulnerability: Vulnerability{
					VendorProject: tt.vendor,
					Product:       tt.product,
					DateAdded:     tt.dateAdded,
				},
			}
			got := item.Description()
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("Description() = %q, want to contain %q", got, substr)
				}
			}
		})
	}
}

func TestVulnerabilityItemFilterValue(t *testing.T) {
	item := VulnerabilityItem{
		Vulnerability: Vulnerability{
			CVEID:             "CVE-2024-1234",
			VendorProject:     "Microsoft",
			Product:           "Exchange",
			VulnerabilityName: "Remote Code Execution",
		},
	}

	got := item.FilterValue()

	// Should contain all searchable fields
	expected := []string{"CVE-2024-1234", "Microsoft", "Exchange", "Remote Code Execution"}
	for _, substr := range expected {
		if !strings.Contains(got, substr) {
			t.Errorf("FilterValue() = %q, want to contain %q", got, substr)
		}
	}
}

func TestVulnerabilityItemFilterValueEmpty(t *testing.T) {
	item := VulnerabilityItem{
		Vulnerability: Vulnerability{},
	}

	// Should not panic on empty vulnerability
	got := item.FilterValue()
	if got == "" {
		// Expected - empty fields joined with spaces results in just spaces
	}
}
