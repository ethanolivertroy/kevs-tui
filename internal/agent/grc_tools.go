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
	Framework string `json:"framework,omitempty" jsonschema:"Framework: nist, fedramp, or cis (default: nist)"`
}

// MapCVEResult for map_cve_to_controls tool
type MapCVEResult struct {
	CVEID       string               `json:"cve_id"`
	Framework   string               `json:"framework"`
	Controls    []grc.ControlSummary `json:"controls,omitempty"`
	CISControls []CISControlSummary  `json:"cis_controls,omitempty"`
	Rationale   string               `json:"rationale"`
	Confidence  float64              `json:"confidence"`
	Found       bool                 `json:"found"`
}

// CISControlSummary provides a summary of a CIS Control
type CISControlSummary struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	ImplementationIG string `json:"implementation_group"` // "IG1", "IG2", "IG3"
	SecurityFunction string `json:"security_function"`
	AssetType        string `json:"asset_type"`
}

// GetControlParams for get_control_details tool
type GetControlParams struct {
	ControlID string `json:"control_id" jsonschema:"Control ID (e.g., SI-2, RA-5 for NIST/FedRAMP, or 7.1, 10.1 for CIS)"`
	Framework string `json:"framework,omitempty" jsonschema:"Framework: nist, fedramp, or cis (default: nist)"`
}

// GetControlResult for get_control_details tool
type GetControlResult struct {
	Found      bool                `json:"found"`
	Control    grc.SecurityControl `json:"control,omitempty"`
	CISControl *grc.CISControl     `json:"cis_control,omitempty"`
}

// ListControlsParams for list_controls tool
type ListControlsParams struct {
	Family              string `json:"family,omitempty" jsonschema:"For NIST/FedRAMP: filter by control family (e.g., 'Incident Response'). For CIS: filter by security function (e.g., 'Protect', 'Detect')"`
	Framework           string `json:"framework,omitempty" jsonschema:"Framework: nist, fedramp, or cis (default: nist)"`
	ImplementationGroup int    `json:"implementation_group,omitempty" jsonschema:"For CIS only: filter by implementation group (1, 2, or 3)"`
}

// ListControlsResult for list_controls tool
type ListControlsResult struct {
	Count       int                   `json:"count"`
	Controls    []grc.SecurityControl `json:"controls,omitempty"`
	CISControls []grc.CISControl      `json:"cis_controls,omitempty"`
}

// --- GRC Tool Implementations ---

func mapCVEToControls(ctx tool.Context, params MapCVEParams) (MapCVEResult, error) {
	if err := ensureKEVData(); err != nil {
		return MapCVEResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	framework := strings.ToLower(params.Framework)
	if framework == "" {
		framework = "nist"
	}

	cveID := strings.ToUpper(params.CVEID)

	// Find the vulnerability
	var found bool
	for _, v := range kevCache {
		if v.CVEID == cveID {
			found = true

			// Handle CIS framework separately
			if framework == "cis" {
				cisMapping := grcMapper.MapVulnerabilityToCIS(v)

				// Convert CIS controls to summaries
				var cisSummaries []CISControlSummary
				for _, ctrl := range cisMapping.Controls {
					ig := "IG3"
					if ctrl.IG1 {
						ig = "IG1"
					} else if ctrl.IG2 {
						ig = "IG2"
					}
					cisSummaries = append(cisSummaries, CISControlSummary{
						ID:               ctrl.ID,
						Title:            ctrl.Title,
						ImplementationIG: ig,
						SecurityFunction: ctrl.SecurityFunction,
						AssetType:        ctrl.AssetType,
					})
				}

				return MapCVEResult{
					CVEID:       cisMapping.CVEID,
					Framework:   "cis",
					CISControls: cisSummaries,
					Rationale:   cisMapping.Rationale,
					Confidence:  cisMapping.Confidence,
					Found:       true,
				}, nil
			}

			// Map to NIST/FedRAMP controls
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
	framework := strings.ToLower(params.Framework)
	if framework == "" {
		framework = "nist"
	}

	// Handle CIS framework
	if framework == "cis" {
		ctrl, ok := grcMapper.GetCISControl(params.ControlID)
		if !ok {
			return GetControlResult{Found: false}, nil
		}
		return GetControlResult{
			Found:      true,
			CISControl: &ctrl,
		}, nil
	}

	// Handle NIST/FedRAMP
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
	framework := strings.ToLower(params.Framework)
	if framework == "" {
		framework = "nist"
	}

	// Handle CIS framework
	if framework == "cis" {
		cisControls := grcMapper.ListCISControls(params.ImplementationGroup, params.Family)
		return ListControlsResult{
			Count:       len(cisControls),
			CISControls: cisControls,
		}, nil
	}

	// Handle NIST/FedRAMP
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
			Description: "Map a CVE from the KEV catalog to security controls. Supports NIST 800-53, FedRAMP, and CIS Controls v8 frameworks. Returns applicable controls with rationale explaining why each control applies.",
		},
		mapCVEToControls,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create map_cve_to_controls tool: %w", err)
	}

	getControlTool, err := functiontool.New(
		functiontool.Config{
			Name:        "get_control_details",
			Description: "Get detailed information about a specific security control. Supports NIST 800-53 (e.g., SI-2, RA-5), FedRAMP, and CIS Controls v8 (e.g., 7.1, 10.1). Returns description, priority/implementation group, and applicable baselines.",
		},
		getControlDetails,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_control_details tool: %w", err)
	}

	listControlsTool, err := functiontool.New(
		functiontool.Config{
			Name:        "list_controls",
			Description: "List available security controls from NIST 800-53, FedRAMP, or CIS Controls v8. For NIST/FedRAMP, filter by control family. For CIS, filter by implementation group (IG1/IG2/IG3) or security function (Identify, Protect, Detect, Respond, Recover).",
		},
		listControls,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create list_controls tool: %w", err)
	}

	return []tool.Tool{mapTool, getControlTool, listControlsTool}, nil
}
