package grc

import (
	"fmt"
	"strings"

	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

// Mapper handles KEV to control mapping
type Mapper struct {
	nistControls    map[string]SecurityControl
	fedrampControls map[string]SecurityControl
	cweMapping      map[string][]string
}

// NewMapper creates a new control mapper
func NewMapper() *Mapper {
	return &Mapper{
		nistControls:    NIST80053Controls,
		fedrampControls: FedRAMPControls,
		cweMapping:      CWEToControlMapping,
	}
}

// MapVulnerability maps a KEV entry to applicable controls
func (m *Mapper) MapVulnerability(vuln model.Vulnerability, framework string) ControlMapping {
	mapping := ControlMapping{
		CVEID:    vuln.CVEID,
		Controls: []SecurityControl{},
	}

	controlSet := make(map[string]bool)
	var rationale []string

	// Always applicable controls for KEV entries
	baseControls := []string{"SI-2", "RA-5", "CM-8", "CA-7"}
	for _, id := range baseControls {
		controlSet[id] = true
	}
	rationale = append(rationale, "KEV entry requires vulnerability scanning (RA-5) and flaw remediation (SI-2)")

	// Map based on CWEs
	for _, cwe := range vuln.CWEs {
		// Normalize CWE format (handle "CWE-78" or just "78")
		normalizedCWE := strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
		fullCWE := "CWE-" + normalizedCWE

		if controls, ok := m.cweMapping[fullCWE]; ok {
			for _, ctrlID := range controls {
				controlSet[ctrlID] = true
			}
			rationale = append(rationale, fmt.Sprintf("%s maps to additional controls", fullCWE))
		}
	}

	// Ransomware-associated CVEs get additional controls
	if vuln.RansomwareUse {
		ransomwareControls := []string{"IR-4", "IR-6", "SI-3", "SC-7", "CP-9", "CP-10"}
		for _, id := range ransomwareControls {
			controlSet[id] = true
		}
		rationale = append(rationale, "Ransomware association requires incident response (IR-4, IR-6), malware protection (SI-3), and backup/recovery (CP-9, CP-10)")
	}

	// EPSS-based severity mapping
	if vuln.EPSS.Score >= 0.7 {
		// High exploitation probability - add enhanced monitoring
		controlSet["SI-4"] = true // System Monitoring
		controlSet["AU-6"] = true // Audit Record Review
		rationale = append(rationale, fmt.Sprintf("High EPSS score (%.0f%%) requires enhanced monitoring (SI-4, AU-6)", vuln.EPSS.Score*100))
	} else if vuln.EPSS.Score >= 0.3 {
		controlSet["SI-4"] = true
		rationale = append(rationale, fmt.Sprintf("Moderate EPSS score (%.0f%%) suggests system monitoring (SI-4)", vuln.EPSS.Score*100))
	}

	// Build final control list from the appropriate framework
	source := m.nistControls
	if strings.ToLower(framework) == "fedramp" {
		source = m.fedrampControls
	}

	for id := range controlSet {
		if ctrl, ok := source[id]; ok {
			mapping.Controls = append(mapping.Controls, ctrl)
		} else if ctrl, ok := m.nistControls[id]; ok {
			// Fall back to NIST if not in FedRAMP
			mapping.Controls = append(mapping.Controls, ctrl)
		}
	}

	mapping.Rationale = strings.Join(rationale, "; ")
	mapping.Confidence = m.calculateConfidence(vuln, len(mapping.Controls))

	return mapping
}

// calculateConfidence determines mapping confidence based on data quality
func (m *Mapper) calculateConfidence(vuln model.Vulnerability, controlCount int) float64 {
	confidence := 0.5 // Base confidence

	// More CWEs = higher confidence
	if len(vuln.CWEs) > 0 {
		confidence += 0.2
	}
	if len(vuln.CWEs) > 2 {
		confidence += 0.1
	}

	// EPSS data available
	if vuln.EPSS.Score > 0 {
		confidence += 0.1
	}

	// More controls mapped = higher confidence (up to a point)
	if controlCount >= 3 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

// GetControl returns a specific control by ID
func (m *Mapper) GetControl(controlID, framework string) (SecurityControl, bool) {
	source := m.nistControls
	if strings.ToLower(framework) == "fedramp" {
		source = m.fedrampControls
	}

	ctrl, ok := source[controlID]
	if !ok && framework != "" {
		// Try NIST as fallback
		ctrl, ok = m.nistControls[controlID]
	}
	return ctrl, ok
}

// ListControls returns all controls, optionally filtered by family
func (m *Mapper) ListControls(framework, family string) []SecurityControl {
	source := m.nistControls
	if strings.ToLower(framework) == "fedramp" {
		source = m.fedrampControls
	}

	var controls []SecurityControl
	for _, ctrl := range source {
		if family == "" || strings.Contains(strings.ToLower(ctrl.Family), strings.ToLower(family)) {
			controls = append(controls, ctrl)
		}
	}
	return controls
}

// GetAllControlIDs returns all control IDs in the specified framework
func (m *Mapper) GetAllControlIDs(framework string) []string {
	source := m.nistControls
	if strings.ToLower(framework) == "fedramp" {
		source = m.fedrampControls
	}

	ids := make([]string, 0, len(source))
	for id := range source {
		ids = append(ids, id)
	}
	return ids
}
