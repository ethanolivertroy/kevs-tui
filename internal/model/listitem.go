package model

import (
	"fmt"
	"strings"
)

// VulnerabilityItem wraps Vulnerability to implement list.Item interface
type VulnerabilityItem struct {
	Vulnerability
}

// Title returns the display title for the list
func (v VulnerabilityItem) Title() string {
	return v.VulnerabilityName
}

// Description returns the secondary text for the list
func (v VulnerabilityItem) Description() string {
	dateStr := ""
	if !v.DateAdded.IsZero() {
		dateStr = v.DateAdded.Format("2006-01-02")
	}
	return fmt.Sprintf("%s | %s | Added: %s", v.VendorProject, v.Product, dateStr)
}

// FilterValue returns the string used for filtering
func (v VulnerabilityItem) FilterValue() string {
	return strings.Join([]string{
		v.CVEID,
		v.VendorProject,
		v.Product,
		v.VulnerabilityName,
	}, " ")
}
