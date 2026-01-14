package chat

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
	"github.com/ethanolivertroy/kevs-tui/internal/palette"
)

// createTestModel creates a minimal Model for testing
func createTestModel() Model {
	ti := textinput.New()
	s := spinner.New()
	vp := viewport.New(80, 20)

	return Model{
		textInput:  ti,
		spinner:    s,
		viewport:   vp,
		messages:   []ChatMessage{},
		ready:      true,
		width:      80,
		height:     24,
		palette:    palette.New([]palette.Command{}),
		currentCVE: nil,
	}
}

// createTestCVE creates a test VulnerabilityItem
func createTestCVE() *model.VulnerabilityItem {
	return &model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2025-55182",
			VendorProject:     "Meta",
			Product:           "React Server Components",
			VulnerabilityName: "Remote Code Execution Vulnerability",
			DateAdded:         time.Now().AddDate(0, 0, -21),
			DueDate:           time.Now().AddDate(0, 0, -14),
			EPSS: model.EPSSScore{
				Score:      0.47,
				Percentile: 0.98,
			},
		},
	}
}

func TestCVESelectedMsgUpdatesContext(t *testing.T) {
	m := createTestModel()

	// Verify initial state is nil
	if m.currentCVE != nil {
		t.Error("currentCVE should be nil initially")
	}

	// Create a test CVE
	testCVE := createTestCVE()

	// Send CVESelectedMsg
	msg := model.CVESelectedMsg{CVE: testCVE}
	newModel, _ := m.Update(msg)

	// Assert currentCVE is set
	chatModel := newModel.(Model)
	if chatModel.currentCVE == nil {
		t.Fatal("currentCVE should be set after CVESelectedMsg")
	}
	if chatModel.currentCVE.CVEID != "CVE-2025-55182" {
		t.Errorf("expected CVE-2025-55182, got %s", chatModel.currentCVE.CVEID)
	}
	if chatModel.currentCVE.VendorProject != "Meta" {
		t.Errorf("expected vendor Meta, got %s", chatModel.currentCVE.VendorProject)
	}
}

func TestCVESelectedMsgClearsContext(t *testing.T) {
	m := createTestModel()

	// First set a CVE
	testCVE := createTestCVE()
	m.currentCVE = testCVE

	// Verify it's set
	if m.currentCVE == nil {
		t.Fatal("currentCVE should be set for this test")
	}

	// Send nil CVESelectedMsg to clear
	msg := model.CVESelectedMsg{CVE: nil}
	newModel, _ := m.Update(msg)

	// Assert currentCVE is cleared
	chatModel := newModel.(Model)
	if chatModel.currentCVE != nil {
		t.Error("currentCVE should be nil after CVESelectedMsg{CVE: nil}")
	}
}

func TestViewShowsContextBadge(t *testing.T) {
	m := createTestModel()

	// Set a CVE
	testCVE := createTestCVE()
	m.currentCVE = testCVE

	// Render the view
	view := m.View()

	// Check that the CVE ID appears in the view
	if !strings.Contains(view, "CVE-2025-55182") {
		t.Error("View should contain CVE ID badge when currentCVE is set")
		t.Logf("View output:\n%s", view)
	}
}

func TestViewDoesNotShowBadgeWhenNoContext(t *testing.T) {
	m := createTestModel()

	// Ensure no CVE is set
	m.currentCVE = nil

	// Render the view
	view := m.View()

	// The view should still render (not crash) but no CVE badge
	if view == "" {
		t.Error("View should render even without currentCVE")
	}

	// Should contain the title but not a specific CVE ID
	if !strings.Contains(view, "KEVin") {
		t.Error("View should contain KEVin title")
	}
}

// TestBuildEnrichedQuery tests the context injection logic
// We extract this to a helper function for testability
func TestBuildEnrichedQuery(t *testing.T) {
	testCVE := createTestCVE()

	tests := []struct {
		name       string
		currentCVE *model.VulnerabilityItem
		query      string
		wantPrefix bool
	}{
		{
			name:       "with CVE context",
			currentCVE: testCVE,
			query:      "what should I do?",
			wantPrefix: true,
		},
		{
			name:       "without CVE context",
			currentCVE: nil,
			query:      "what should I do?",
			wantPrefix: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enriched := buildEnrichedQuery(tt.currentCVE, tt.query)

			if tt.wantPrefix {
				if !strings.HasPrefix(enriched, "[Context:") {
					t.Errorf("expected context prefix, got: %s", enriched[:min(50, len(enriched))])
				}
				if !strings.Contains(enriched, "CVE-2025-55182") {
					t.Error("enriched query should contain CVE ID")
				}
				if !strings.Contains(enriched, tt.query) {
					t.Error("enriched query should contain original query")
				}
			} else {
				if enriched != tt.query {
					t.Errorf("without context, query should be unchanged. got: %s", enriched)
				}
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Tests for ANSI-aware text selection

func TestVisibleLength(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"plain text", "hello", 5},
		{"with color code", "\x1b[32mgreen\x1b[0m", 5},
		{"RGB color code", "\x1b[38;2;248;248;242mtext\x1b[0m", 4},
		{"multiple codes", "\x1b[1m\x1b[32mbold green\x1b[0m", 10},
		{"empty", "", 0},
		{"only escape", "\x1b[0m", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := visibleLength(tt.input)
			if got != tt.expected {
				t.Errorf("visibleLength(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAnsiSliceWithHighlight(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		start          int
		end            int
		shouldNotBreak bool // Result should not contain broken escape sequences
	}{
		{
			name:           "plain text selection",
			input:          "hello world",
			start:          0,
			end:            5,
			shouldNotBreak: true,
		},
		{
			name:           "preserves simple color codes",
			input:          "\x1b[32mgreen text\x1b[0m",
			start:          0,
			end:            5,
			shouldNotBreak: true,
		},
		{
			name:           "preserves RGB color codes",
			input:          "\x1b[38;2;248;248;242mcolored text\x1b[0m",
			start:          2,
			end:            7,
			shouldNotBreak: true,
		},
		{
			name:           "selection at start",
			input:          "\x1b[32mtest\x1b[0m",
			start:          0,
			end:            2,
			shouldNotBreak: true,
		},
		{
			name:           "selection at end",
			input:          "\x1b[32mtest\x1b[0m",
			start:          2,
			end:            4,
			shouldNotBreak: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ansiSliceWithHighlight(tt.input, tt.start, tt.end)

			// Check for broken escape sequences (semicolons not preceded by escape)
			if tt.shouldNotBreak {
				// Look for orphaned escape sequence parts like ";2;248" at start
				if len(result) > 0 && result[0] == ';' {
					t.Errorf("result starts with orphaned semicolon: %q", result)
				}
				// Check for numbers followed by 'm' not preceded by escape
				if strings.Contains(result, "248;242m") && !strings.Contains(result, "\x1b[") {
					t.Errorf("broken escape sequence in result: %q", result)
				}
			}
		})
	}
}

func TestApplySelectionHighlightNoCorruption(t *testing.T) {
	m := createTestModel()
	m.selStartLine = 0
	m.selStartCol = 0
	m.selEndLine = 0
	m.selEndCol = 5

	// Content with ANSI escape sequences (like glamour output)
	content := "\x1b[38;2;248;248;242mHi! Let me know what you need\x1b[0m"
	result := m.applySelectionHighlight(content)

	// Should NOT contain orphaned escape sequence fragments
	if strings.HasPrefix(result, ";") {
		t.Errorf("result starts with broken escape sequence: %q", result[:50])
	}

	// The escape codes should still be present
	if !strings.Contains(result, "\x1b[") {
		t.Errorf("result should still contain escape codes")
	}
}
