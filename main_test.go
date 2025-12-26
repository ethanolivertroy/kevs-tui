package main

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethanolivertroy/kevs-tui/internal/chat"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

func TestCVESelectedMsgRoutedToAgent(t *testing.T) {
	// Create an AppModel with a minimal chat model
	app := newAppModel()

	// Manually set up a mock agent model (use nil agent/ctx since we just need Update to work)
	app.agentModel = chat.NewModel(nil, nil)
	app.agentInitialized = true
	app.width = 120
	app.height = 30

	// Create a test CVE
	testCVE := &model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2025-12345",
			VendorProject:     "TestVendor",
			Product:           "TestProduct",
			VulnerabilityName: "Test Vulnerability",
			DateAdded:         time.Now(),
			DueDate:           time.Now().Add(24 * time.Hour),
		},
	}

	// Send CVESelectedMsg to AppModel
	msg := model.CVESelectedMsg{CVE: testCVE}
	newApp, _ := app.Update(msg)

	updatedApp := newApp.(AppModel)

	// Check if the agent model received the message
	// We need to check the chat model's internal state
	if updatedApp.agentModel == nil {
		t.Fatal("agentModel should not be nil")
	}

	// Type assert to chat.Model to check currentCVE
	chatModel, ok := updatedApp.agentModel.(chat.Model)
	if !ok {
		t.Fatalf("agentModel is not chat.Model, got %T", updatedApp.agentModel)
	}

	// The chat model should now have the CVE context
	if chatModel.CurrentCVE() == nil {
		t.Error("CVE context was not set in chat model after CVESelectedMsg")
	} else if chatModel.CurrentCVE().CVEID != "CVE-2025-12345" {
		t.Errorf("Expected CVE-2025-12345, got %s", chatModel.CurrentCVE().CVEID)
	}
}

func TestCVESelectedMsgNotRoutedWhenAgentNil(t *testing.T) {
	// Create an AppModel WITHOUT an agent model
	app := newAppModel()
	// agentModel is nil by default

	// Create a test CVE
	testCVE := &model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID: "CVE-2025-99999",
		},
	}

	// Send CVESelectedMsg - should not panic
	msg := model.CVESelectedMsg{CVE: testCVE}
	newApp, cmd := app.Update(msg)

	// Should return without error
	if newApp == nil {
		t.Error("Update returned nil model")
	}

	// Command should be empty batch (no-op)
	if cmd != nil {
		// tea.Batch with empty slice returns nil, so this is expected
		t.Log("Command returned (expected nil or empty batch)")
	}
}

func TestClosureCapturesCorrectValue(t *testing.T) {
	// Simulate what happens in TUI when entering detail view
	// This tests that the closure correctly captures the item variable

	testCVE := model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2025-CLOSURE",
			VendorProject:     "ClosureTest",
			Product:           "TestProduct",
			VulnerabilityName: "Closure Test Vulnerability",
		},
	}

	// Simulate the closure creation (like line 262 in app.go)
	item := testCVE // Local variable
	cveMsg := func() interface{} { return model.CVESelectedMsg{CVE: &item} }

	// Execute the closure (simulating what Bubble Tea does)
	result := cveMsg()

	msg, ok := result.(model.CVESelectedMsg)
	if !ok {
		t.Fatalf("Expected CVESelectedMsg, got %T", result)
	}

	if msg.CVE == nil {
		t.Fatal("CVE should not be nil")
	}

	if msg.CVE.CVEID != "CVE-2025-CLOSURE" {
		t.Errorf("Expected CVE-2025-CLOSURE, got %s", msg.CVE.CVEID)
	}

	// Also verify the pointer is valid
	if msg.CVE.VendorProject != "ClosureTest" {
		t.Errorf("Expected ClosureTest, got %s", msg.CVE.VendorProject)
	}
}

func TestClosureWithinIfBlock(t *testing.T) {
	// More precise simulation of the if block pattern in app.go
	type Item struct {
		ID   string
		Name string
	}

	getItem := func() (Item, bool) {
		return Item{ID: "test-id", Name: "Test Name"}, true
	}

	var capturedClosure func() interface{}

	if item, ok := getItem(); ok {
		// This mirrors the exact pattern in app.go line 262
		capturedClosure = func() interface{} { return &item }
	}

	if capturedClosure == nil {
		t.Fatal("Closure should have been created")
	}

	// Execute the closure after the if block
	result := capturedClosure()
	ptr, ok := result.(*Item)
	if !ok {
		t.Fatalf("Expected *Item, got %T", result)
	}

	if ptr.ID != "test-id" {
		t.Errorf("Expected test-id, got %s", ptr.ID)
	}
}

func TestCVEContextPreservedAcrossAgentInit(t *testing.T) {
	// This test verifies that CVE context is preserved when user navigates to
	// detail view BEFORE agent finishes initializing

	// Create AppModel WITHOUT agent model (simulating before agent init completes)
	app := newAppModel()
	// agentModel is nil at this point

	// Create a CVE
	testCVE := model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2025-PRESERVED",
			VendorProject:     "PreservedTest",
			Product:           "TestProduct",
			VulnerabilityName: "Preserved Context Vulnerability",
		},
	}

	// User navigates to detail view - CVESelectedMsg is sent
	item := testCVE
	cveCmd := func() tea.Msg { return model.CVESelectedMsg{CVE: &item} }
	msg := cveCmd()
	newApp, _ := app.Update(msg)
	app = newApp.(AppModel)

	// Verify pendingCVE is stored
	if app.pendingCVE == nil {
		t.Fatal("pendingCVE should be stored when agent is not initialized")
	}
	if app.pendingCVE.CVEID != "CVE-2025-PRESERVED" {
		t.Errorf("Expected CVE-2025-PRESERVED, got %s", app.pendingCVE.CVEID)
	}

	// Now agent initializes (simulating agentInitMsg)
	// We need to simulate the actual agentInitMsg handling
	initMsg := agentInitMsg{agent: nil, ctx: nil}
	newApp2, _ := app.Update(initMsg)
	app = newApp2.(AppModel)

	// Send window size
	sizeMsg := tea.WindowSizeMsg{Width: 45, Height: 30}
	newApp3, _ := app.Update(sizeMsg)
	app = newApp3.(AppModel)

	// Check if the chat model has the CVE context
	chatModel := app.agentModel.(chat.Model)
	if chatModel.CurrentCVE() == nil {
		t.Fatal("CVE context should be preserved after agent initialization")
	}
	if chatModel.CurrentCVE().CVEID != "CVE-2025-PRESERVED" {
		t.Errorf("Expected CVE-2025-PRESERVED, got %s", chatModel.CurrentCVE().CVEID)
	}
	t.Log("SUCCESS: CVE context is preserved across agent initialization")
}

func TestFullMessageFlow(t *testing.T) {
	// This test simulates the full message flow from TUI returning a command
	// to the chat model receiving the CVESelectedMsg

	// Create AppModel with chat model
	app := newAppModel()
	app.agentModel = chat.NewModel(nil, nil)
	app.agentInitialized = true
	app.width = 120
	app.height = 30

	// Initialize the chat model with proper dimensions
	initCmd := app.agentModel.Init()
	if initCmd != nil {
		// Execute init command if any
		_ = initCmd()
	}
	sizeMsg := tea.WindowSizeMsg{Width: 45, Height: 30}
	app.agentModel, _ = app.agentModel.Update(sizeMsg)

	// Create a CVE and simulate the command that would be returned by TUI
	testCVE := model.VulnerabilityItem{
		Vulnerability: model.Vulnerability{
			CVEID:             "CVE-2025-FLOW",
			VendorProject:     "FlowTest",
			Product:           "TestProduct",
			VulnerabilityName: "Flow Test Vulnerability",
			DateAdded:         time.Now(),
			DueDate:           time.Now().Add(24 * time.Hour),
		},
	}

	// Simulate the closure that TUI would create (like line 262 in app.go)
	item := testCVE
	cveCmd := func() tea.Msg { return model.CVESelectedMsg{CVE: &item} }

	// Execute the command to get the message
	msg := cveCmd()

	// Route the message through AppModel
	newApp, _ := app.Update(msg)
	updatedApp := newApp.(AppModel)

	// Verify the chat model received the message
	chatModel := updatedApp.agentModel.(chat.Model)
	if chatModel.CurrentCVE() == nil {
		t.Fatal("CVE context was not set after message flow")
	}

	if chatModel.CurrentCVE().CVEID != "CVE-2025-FLOW" {
		t.Errorf("Expected CVE-2025-FLOW, got %s", chatModel.CurrentCVE().CVEID)
	}

	// Verify the View shows the badge
	view := chatModel.View()
	if !strings.Contains(view, "CVE-2025-FLOW") {
		t.Error("Badge should appear in view after CVE context is set")
		t.Logf("View content:\n%s", view)
	}
}
