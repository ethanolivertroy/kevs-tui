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
	cisControls     map[string]CISControl
	cweMapping      map[string][]string
}

// NewMapper creates a new control mapper
func NewMapper() *Mapper {
	return &Mapper{
		nistControls:    NIST80053Controls,
		fedrampControls: FedRAMPControls,
		cisControls:     CISControls,
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

// CISControlMapping holds mapping results for CIS Controls
type CISControlMapping struct {
	CVEID      string       `json:"cve_id"`
	Controls   []CISControl `json:"controls"`
	Rationale  string       `json:"rationale"`
	Confidence float64      `json:"confidence"`
}

// MapVulnerabilityToCIS maps a KEV entry to applicable CIS Controls v8
func (m *Mapper) MapVulnerabilityToCIS(vuln model.Vulnerability) CISControlMapping {
	mapping := CISControlMapping{
		CVEID:    vuln.CVEID,
		Controls: []CISControl{},
	}

	controlSet := make(map[string]bool)
	var rationale []string

	// Base vulnerability management controls always apply for KEV entries
	baseControls := []string{"7.1", "7.2", "7.3", "7.4", "1.1", "2.1"}
	for _, id := range baseControls {
		controlSet[id] = true
	}
	rationale = append(rationale, "KEV entry requires vulnerability management (7.1, 7.2) and patch management (7.3, 7.4)")

	// Map based on CWEs
	for _, cwe := range vuln.CWEs {
		// Normalize CWE format
		normalizedCWE := strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
		fullCWE := "CWE-" + normalizedCWE

		if controls, ok := CWEToCISMapping[fullCWE]; ok {
			for _, ctrlID := range controls {
				controlSet[ctrlID] = true
			}
			rationale = append(rationale, fmt.Sprintf("%s maps to additional CIS controls", fullCWE))
		}
	}

	// Ransomware-associated CVEs get additional controls
	if vuln.RansomwareUse {
		ransomwareControls := []string{"10.1", "10.2", "11.1", "11.2", "11.4", "17.1", "17.2", "17.3"}
		for _, id := range ransomwareControls {
			controlSet[id] = true
		}
		rationale = append(rationale, "Ransomware association requires malware defenses (10.1, 10.2), data recovery (11.1, 11.2, 11.4), and incident response (17.1-17.3)")
	}

	// EPSS-based severity mapping
	if vuln.EPSS.Score >= 0.7 {
		// High exploitation probability - add enhanced monitoring
		controlSet["8.1"] = true  // Audit Log Management
		controlSet["8.2"] = true  // Collect Audit Logs
		controlSet["13.1"] = true // Centralize Security Event Alerting
		rationale = append(rationale, fmt.Sprintf("High EPSS score (%.0f%%) requires enhanced logging and monitoring (8.1, 8.2, 13.1)", vuln.EPSS.Score*100))
	} else if vuln.EPSS.Score >= 0.3 {
		controlSet["8.1"] = true
		controlSet["8.2"] = true
		rationale = append(rationale, fmt.Sprintf("Moderate EPSS score (%.0f%%) suggests audit logging (8.1, 8.2)", vuln.EPSS.Score*100))
	}

	// Build final control list
	for id := range controlSet {
		if ctrl, ok := m.cisControls[id]; ok {
			mapping.Controls = append(mapping.Controls, ctrl)
		}
	}

	mapping.Rationale = strings.Join(rationale, "; ")
	mapping.Confidence = m.calculateConfidence(vuln, len(mapping.Controls))

	return mapping
}

// GetCISControl returns a specific CIS Control by ID
func (m *Mapper) GetCISControl(controlID string) (CISControl, bool) {
	ctrl, ok := m.cisControls[controlID]
	return ctrl, ok
}

// ListCISControls returns all CIS Controls, optionally filtered by implementation group or security function
func (m *Mapper) ListCISControls(implementationGroup int, securityFunction string) []CISControl {
	var controls []CISControl
	for _, ctrl := range m.cisControls {
		// Filter by implementation group if specified
		if implementationGroup > 0 {
			var inGroup bool
			switch implementationGroup {
			case 1:
				inGroup = ctrl.IG1
			case 2:
				inGroup = ctrl.IG2
			case 3:
				inGroup = ctrl.IG3
			}
			if !inGroup {
				continue
			}
		}

		// Filter by security function if specified
		if securityFunction != "" && !strings.EqualFold(ctrl.SecurityFunction, securityFunction) {
			continue
		}

		controls = append(controls, ctrl)
	}
	return controls
}

// GetAllCISControlIDs returns all CIS Control IDs
func (m *Mapper) GetAllCISControlIDs() []string {
	ids := make([]string, 0, len(m.cisControls))
	for id := range m.cisControls {
		ids = append(ids, id)
	}
	return ids
}
