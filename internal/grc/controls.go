// Package grc provides GRC (Governance, Risk, Compliance) control mapping for KEVs
package grc

// SecurityControl represents a NIST 800-53 or FedRAMP control
type SecurityControl struct {
	ID          string   `json:"id"`          // e.g., "SI-2", "RA-5"
	Family      string   `json:"family"`      // e.g., "System and Information Integrity"
	Name        string   `json:"name"`        // e.g., "Flaw Remediation"
	Description string   `json:"description"` // Full control description
	Priority    string   `json:"priority"`    // P1, P2, P3
	Baseline    []string `json:"baseline"`    // ["Low", "Moderate", "High"]
	Framework   string   `json:"framework"`   // "NIST 800-53" or "FedRAMP"
}

// ControlMapping represents a KEV-to-control mapping
type ControlMapping struct {
	CVEID      string            `json:"cve_id"`
	Controls   []SecurityControl `json:"controls"`
	Rationale  string            `json:"rationale"`
	Confidence float64           `json:"confidence"` // 0.0-1.0
}

// ControlSummary is a simplified control representation for API responses
type ControlSummary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Family      string   `json:"family"`
	Priority    string   `json:"priority"`
	Baseline    []string `json:"baseline"`
	Description string   `json:"description,omitempty"`
}

// ToSummary converts a SecurityControl to a ControlSummary
func (c SecurityControl) ToSummary() ControlSummary {
	return ControlSummary{
		ID:          c.ID,
		Name:        c.Name,
		Family:      c.Family,
		Priority:    c.Priority,
		Baseline:    c.Baseline,
		Description: c.Description,
	}
}
