package tui

import (
	"testing"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

func TestGetTopVendors(t *testing.T) {
	tests := []struct {
		name          string
		vulns         []model.Vulnerability
		n             int
		expectedLen   int
		expectedFirst string
		expectedCount int
	}{
		{
			name:        "empty list",
			vulns:       []model.Vulnerability{},
			n:           10,
			expectedLen: 0,
		},
		{
			name: "single vendor",
			vulns: []model.Vulnerability{
				{VendorProject: "Microsoft"},
				{VendorProject: "Microsoft"},
			},
			n:             10,
			expectedLen:   1,
			expectedFirst: "Microsoft",
			expectedCount: 2,
		},
		{
			name: "multiple vendors sorted by count",
			vulns: []model.Vulnerability{
				{VendorProject: "Apple"},
				{VendorProject: "Microsoft"},
				{VendorProject: "Microsoft"},
				{VendorProject: "Microsoft"},
				{VendorProject: "Google"},
				{VendorProject: "Google"},
			},
			n:             10,
			expectedLen:   3,
			expectedFirst: "Microsoft",
			expectedCount: 3,
		},
		{
			name: "limit to N vendors",
			vulns: []model.Vulnerability{
				{VendorProject: "A"},
				{VendorProject: "B"},
				{VendorProject: "C"},
				{VendorProject: "D"},
				{VendorProject: "E"},
			},
			n:           3,
			expectedLen: 3,
		},
		{
			name: "exact N vendors",
			vulns: []model.Vulnerability{
				{VendorProject: "A"},
				{VendorProject: "B"},
				{VendorProject: "C"},
			},
			n:           3,
			expectedLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTopVendors(tt.vulns, tt.n)

			if len(result) != tt.expectedLen {
				t.Errorf("GetTopVendors() returned %d vendors, want %d", len(result), tt.expectedLen)
			}

			if tt.expectedFirst != "" && len(result) > 0 {
				if result[0].Name != tt.expectedFirst {
					t.Errorf("GetTopVendors() first vendor = %q, want %q", result[0].Name, tt.expectedFirst)
				}
				if result[0].Count != tt.expectedCount {
					t.Errorf("GetTopVendors() first count = %d, want %d", result[0].Count, tt.expectedCount)
				}
			}
		})
	}
}

func TestGetMonthlyStats(t *testing.T) {
	now := time.Now()
	thisMonth := time.Date(now.Year(), now.Month(), 15, 0, 0, 0, 0, time.UTC)
	lastMonth := thisMonth.AddDate(0, -1, 0)

	tests := []struct {
		name        string
		vulns       []model.Vulnerability
		months      int
		expectedLen int
	}{
		{
			name:        "empty list returns months with zero counts",
			vulns:       []model.Vulnerability{},
			months:      3,
			expectedLen: 3,
		},
		{
			name: "vulns in current month",
			vulns: []model.Vulnerability{
				{DateAdded: thisMonth},
				{DateAdded: thisMonth},
			},
			months:      3,
			expectedLen: 3,
		},
		{
			name: "vulns across months",
			vulns: []model.Vulnerability{
				{DateAdded: thisMonth},
				{DateAdded: lastMonth},
				{DateAdded: lastMonth},
			},
			months:      3,
			expectedLen: 3,
		},
		{
			name: "zero DateAdded skipped",
			vulns: []model.Vulnerability{
				{DateAdded: time.Time{}},
				{DateAdded: thisMonth},
			},
			months:      3,
			expectedLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMonthlyStats(tt.vulns, tt.months)

			if len(result) != tt.expectedLen {
				t.Errorf("GetMonthlyStats() returned %d months, want %d", len(result), tt.expectedLen)
			}
		})
	}
}

func TestGetMonthlyStatsCountsCorrectly(t *testing.T) {
	now := time.Now()
	thisMonth := time.Date(now.Year(), now.Month(), 15, 0, 0, 0, 0, time.UTC)

	vulns := []model.Vulnerability{
		{DateAdded: thisMonth},
		{DateAdded: thisMonth},
		{DateAdded: thisMonth},
	}

	result := GetMonthlyStats(vulns, 3)

	// The last entry should be the current month
	lastIdx := len(result) - 1
	if result[lastIdx].Count != 3 {
		t.Errorf("Current month count = %d, want 3", result[lastIdx].Count)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"under limit", "short", 10, "short"},
		{"exact limit", "exactly10c", 10, "exactly10c"},
		{"over limit", "this is too long", 10, "this is t."},
		{"one char over", "12345678901", 10, "123456789."},
		{"empty string", "", 10, ""},
		{"max len 1", "abc", 1, "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateString(tt.input, tt.maxLen); got != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expected)
			}
		})
	}
}

func TestGetRansomwareStats(t *testing.T) {
	tests := []struct {
		name            string
		vulns           []model.Vulnerability
		expectedKnown   int
		expectedUnknown int
		expectedTotal   int
	}{
		{
			name:            "empty list",
			vulns:           []model.Vulnerability{},
			expectedKnown:   0,
			expectedUnknown: 0,
			expectedTotal:   0,
		},
		{
			name: "all known ransomware",
			vulns: []model.Vulnerability{
				{RansomwareUse: true},
				{RansomwareUse: true},
			},
			expectedKnown:   2,
			expectedUnknown: 0,
			expectedTotal:   2,
		},
		{
			name: "all unknown ransomware",
			vulns: []model.Vulnerability{
				{RansomwareUse: false},
				{RansomwareUse: false},
			},
			expectedKnown:   0,
			expectedUnknown: 2,
			expectedTotal:   2,
		},
		{
			name: "mixed ransomware usage",
			vulns: []model.Vulnerability{
				{RansomwareUse: true},
				{RansomwareUse: false},
				{RansomwareUse: true},
				{RansomwareUse: false},
				{RansomwareUse: false},
			},
			expectedKnown:   2,
			expectedUnknown: 3,
			expectedTotal:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRansomwareStats(tt.vulns)

			if result.Known != tt.expectedKnown {
				t.Errorf("Known = %d, want %d", result.Known, tt.expectedKnown)
			}
			if result.Unknown != tt.expectedUnknown {
				t.Errorf("Unknown = %d, want %d", result.Unknown, tt.expectedUnknown)
			}
			if result.Total != tt.expectedTotal {
				t.Errorf("Total = %d, want %d", result.Total, tt.expectedTotal)
			}
		})
	}
}

func TestGetTopCWEs(t *testing.T) {
	tests := []struct {
		name          string
		vulns         []model.Vulnerability
		n             int
		expectedLen   int
		expectedFirst string
		expectedCount int
	}{
		{
			name:        "empty list",
			vulns:       []model.Vulnerability{},
			n:           10,
			expectedLen: 0,
		},
		{
			name: "no CWEs",
			vulns: []model.Vulnerability{
				{CWEs: []string{}},
			},
			n:           10,
			expectedLen: 0,
		},
		{
			name: "single CWE",
			vulns: []model.Vulnerability{
				{CWEs: []string{"CWE-79"}},
				{CWEs: []string{"CWE-79"}},
			},
			n:             10,
			expectedLen:   1,
			expectedFirst: "CWE-79",
			expectedCount: 2,
		},
		{
			name: "multiple CWEs sorted by count",
			vulns: []model.Vulnerability{
				{CWEs: []string{"CWE-89", "CWE-79"}},
				{CWEs: []string{"CWE-79"}},
				{CWEs: []string{"CWE-79"}},
				{CWEs: []string{"CWE-20"}},
			},
			n:             10,
			expectedLen:   3,
			expectedFirst: "CWE-79",
			expectedCount: 3,
		},
		{
			name: "limit to N CWEs",
			vulns: []model.Vulnerability{
				{CWEs: []string{"CWE-1"}},
				{CWEs: []string{"CWE-2"}},
				{CWEs: []string{"CWE-3"}},
				{CWEs: []string{"CWE-4"}},
				{CWEs: []string{"CWE-5"}},
			},
			n:           3,
			expectedLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTopCWEs(tt.vulns, tt.n)

			if len(result) != tt.expectedLen {
				t.Errorf("GetTopCWEs() returned %d CWEs, want %d", len(result), tt.expectedLen)
			}

			if tt.expectedFirst != "" && len(result) > 0 {
				if result[0].ID != tt.expectedFirst {
					t.Errorf("GetTopCWEs() first CWE = %q, want %q", result[0].ID, tt.expectedFirst)
				}
				if result[0].Count != tt.expectedCount {
					t.Errorf("GetTopCWEs() first count = %d, want %d", result[0].Count, tt.expectedCount)
				}
			}
		})
	}
}

func TestGetRiskStats(t *testing.T) {
	tests := []struct {
		name             string
		vulns            []model.Vulnerability
		expectedCritical int
		expectedHigh     int
		expectedMedium   int
		expectedLow      int
	}{
		{
			name:             "empty list",
			vulns:            []model.Vulnerability{},
			expectedCritical: 0,
			expectedHigh:     0,
			expectedMedium:   0,
			expectedLow:      0,
		},
		{
			name: "all critical (EPSS >= 0.7)",
			vulns: []model.Vulnerability{
				{EPSS: model.EPSSScore{Score: 0.9}},
				{EPSS: model.EPSSScore{Score: 0.7}},
			},
			expectedCritical: 2,
			expectedHigh:     0,
			expectedMedium:   0,
			expectedLow:      0,
		},
		{
			name: "all high (0.4 <= EPSS < 0.7)",
			vulns: []model.Vulnerability{
				{EPSS: model.EPSSScore{Score: 0.5}},
				{EPSS: model.EPSSScore{Score: 0.4}},
				{EPSS: model.EPSSScore{Score: 0.69}},
			},
			expectedCritical: 0,
			expectedHigh:     3,
			expectedMedium:   0,
			expectedLow:      0,
		},
		{
			name: "all medium (0.1 <= EPSS < 0.4)",
			vulns: []model.Vulnerability{
				{EPSS: model.EPSSScore{Score: 0.2}},
				{EPSS: model.EPSSScore{Score: 0.1}},
				{EPSS: model.EPSSScore{Score: 0.39}},
			},
			expectedCritical: 0,
			expectedHigh:     0,
			expectedMedium:   3,
			expectedLow:      0,
		},
		{
			name: "all low (EPSS < 0.1)",
			vulns: []model.Vulnerability{
				{EPSS: model.EPSSScore{Score: 0.05}},
				{EPSS: model.EPSSScore{Score: 0.0}},
				{EPSS: model.EPSSScore{Score: 0.09}},
			},
			expectedCritical: 0,
			expectedHigh:     0,
			expectedMedium:   0,
			expectedLow:      3,
		},
		{
			name: "mixed risk levels",
			vulns: []model.Vulnerability{
				{EPSS: model.EPSSScore{Score: 0.9}},  // Critical
				{EPSS: model.EPSSScore{Score: 0.5}},  // High
				{EPSS: model.EPSSScore{Score: 0.2}},  // Medium
				{EPSS: model.EPSSScore{Score: 0.05}}, // Low
				{EPSS: model.EPSSScore{Score: 0.0}},  // Low
			},
			expectedCritical: 1,
			expectedHigh:     1,
			expectedMedium:   1,
			expectedLow:      2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRiskStats(tt.vulns)

			if result.Critical != tt.expectedCritical {
				t.Errorf("Critical = %d, want %d", result.Critical, tt.expectedCritical)
			}
			if result.High != tt.expectedHigh {
				t.Errorf("High = %d, want %d", result.High, tt.expectedHigh)
			}
			if result.Medium != tt.expectedMedium {
				t.Errorf("Medium = %d, want %d", result.Medium, tt.expectedMedium)
			}
			if result.Low != tt.expectedLow {
				t.Errorf("Low = %d, want %d", result.Low, tt.expectedLow)
			}
		})
	}
}
