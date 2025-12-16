package tui

import "testing"

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
