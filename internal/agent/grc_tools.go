package agent

import (
	"fmt"
	"strings"

	"github.com/ethanolivertroy/kevs-tui/internal/grc"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
)

// Shared GRC mapper
var grcMapper = grc.NewMapper()

// --- GRC Tool Input/Output Types ---

// MapCVEParams for map_cve_to_controls tool
type MapCVEParams struct {
	CVEID     string `json:"cve_id" jsonschema:"CVE ID to map to controls (e.g., CVE-2024-1234)"`
	Framework string `json:"framework,omitempty" jsonschema:"Framework: nist or fedramp (default: nist)"`
}

// MapCVEResult for map_cve_to_controls tool
type MapCVEResult struct {
	CVEID      string               `json:"cve_id"`
	Framework  string               `json:"framework"`
	Controls   []grc.ControlSummary `json:"controls"`
	Rationale  string               `json:"rationale"`
	Confidence float64              `json:"confidence"`
	Found      bool                 `json:"found"`
}

// GetControlParams for get_control_details tool
type GetControlParams struct {
	ControlID string `json:"control_id" jsonschema:"Control ID (e.g., SI-2, RA-5)"`
	Framework string `json:"framework,omitempty" jsonschema:"Framework: nist or fedramp (default: nist)"`
}

// GetControlResult for get_control_details tool
type GetControlResult struct {
	Found   bool                `json:"found"`
	Control grc.SecurityControl `json:"control,omitempty"`
}

// ListControlsParams for list_controls tool
type ListControlsParams struct {
	Family    string `json:"family,omitempty" jsonschema:"Filter by control family (e.g., 'Incident Response', 'Access Control')"`
	Framework string `json:"framework,omitempty" jsonschema:"Framework: nist or fedramp (default: nist)"`
}

// ListControlsResult for list_controls tool
type ListControlsResult struct {
	Count    int                   `json:"count"`
	Controls []grc.SecurityControl `json:"controls"`
}

// --- GRC Tool Implementations ---

func mapCVEToControls(ctx tool.Context, params MapCVEParams) (MapCVEResult, error) {
	if err := ensureKEVData(); err != nil {
		return MapCVEResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	framework := params.Framework
	if framework == "" {
		framework = "nist"
	}

	cveID := strings.ToUpper(params.CVEID)

	// Find the vulnerability
	var found bool
	for _, v := range kevCache {
		if v.CVEID == cveID {
			found = true

			// Map to controls
			mapping := grcMapper.MapVulnerability(v, framework)

			// Convert controls to summaries
			var summaries []grc.ControlSummary
			for _, ctrl := range mapping.Controls {
				summaries = append(summaries, ctrl.ToSummary())
			}

			return MapCVEResult{
				CVEID:      mapping.CVEID,
				Framework:  framework,
				Controls:   summaries,
				Rationale:  mapping.Rationale,
				Confidence: mapping.Confidence,
				Found:      true,
			}, nil
		}
	}

	if !found {
		return MapCVEResult{
			CVEID:     cveID,
			Framework: framework,
			Rationale: "CVE not found in KEV catalog",
			Found:     false,
		}, nil
	}

	return MapCVEResult{}, nil
}

func getControlDetails(ctx tool.Context, params GetControlParams) (GetControlResult, error) {
	framework := params.Framework
	if framework == "" {
		framework = "nist"
	}

	controlID := strings.ToUpper(params.ControlID)
	ctrl, ok := grcMapper.GetControl(controlID, framework)

	if !ok {
		return GetControlResult{Found: false}, nil
	}

	return GetControlResult{
		Found:   true,
		Control: ctrl,
	}, nil
}

func listControls(ctx tool.Context, params ListControlsParams) (ListControlsResult, error) {
	framework := params.Framework
	if framework == "" {
		framework = "nist"
	}

	controls := grcMapper.ListControls(framework, params.Family)

	return ListControlsResult{
		Count:    len(controls),
		Controls: controls,
	}, nil
}

// CreateGRCTools creates GRC-related tools for the agent
func CreateGRCTools() ([]tool.Tool, error) {
	mapTool, err := functiontool.New(
		functiontool.Config{
			Name:        "map_cve_to_controls",
			Description: "Map a CVE from the KEV catalog to NIST 800-53 or FedRAMP security controls. Returns applicable controls with rationale explaining why each control applies.",
		},
		mapCVEToControls,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create map_cve_to_controls tool: %w", err)
	}

	getControlTool, err := functiontool.New(
		functiontool.Config{
			Name:        "get_control_details",
			Description: "Get detailed information about a specific NIST 800-53 or FedRAMP security control including its description, priority, and applicable baselines.",
		},
		getControlDetails,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_control_details tool: %w", err)
	}

	listControlsTool, err := functiontool.New(
		functiontool.Config{
			Name:        "list_controls",
			Description: "List available NIST 800-53 or FedRAMP security controls, optionally filtered by control family (e.g., 'Incident Response', 'Access Control', 'System and Information Integrity').",
		},
		listControls,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create list_controls tool: %w", err)
	}

	return []tool.Tool{mapTool, getControlTool, listControlsTool}, nil
}
