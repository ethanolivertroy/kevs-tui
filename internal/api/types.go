package api

// KEVResponse represents the top-level JSON response from CISA KEV catalog
type KEVResponse struct {
	Title           string              `json:"title"`
	CatalogVersion  string              `json:"catalogVersion"`
	DateReleased    string              `json:"dateReleased"`
	Count           int                 `json:"count"`
	Vulnerabilities []VulnerabilityJSON `json:"vulnerabilities"`
}

// VulnerabilityJSON represents a single vulnerability entry from the API
type VulnerabilityJSON struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// EPSSResponse represents the response from the EPSS API
type EPSSResponse struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Total      int        `json:"total"`
	Data       []EPSSData `json:"data"`
}

// EPSSData represents a single EPSS score entry
type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// NVDResponse represents the response from the NVD CVE API
type NVDResponse struct {
	ResultsPerPage  int              `json:"resultsPerPage"`
	StartIndex      int              `json:"startIndex"`
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []NVDVulnWrapper `json:"vulnerabilities"`
}

// NVDVulnWrapper wraps a CVE item
type NVDVulnWrapper struct {
	CVE NVDCVEItem `json:"cve"`
}

// NVDCVEItem represents a CVE from NVD
type NVDCVEItem struct {
	ID      string     `json:"id"`
	Metrics NVDMetrics `json:"metrics"`
}

// NVDMetrics contains CVSS score data
type NVDMetrics struct {
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetricV30 `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2"`
}

// CVSSMetricV31 represents CVSS v3.1 metric data
type CVSSMetricV31 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CVSSData CVSSData `json:"cvssData"`
}

// CVSSMetricV30 represents CVSS v3.0 metric data
type CVSSMetricV30 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CVSSData CVSSData `json:"cvssData"`
}

// CVSSMetricV2 represents CVSS v2.0 metric data
type CVSSMetricV2 struct {
	Source       string     `json:"source"`
	Type         string     `json:"type"`
	CVSSData     CVSSDataV2 `json:"cvssData"`
	BaseSeverity string     `json:"baseSeverity"`
}

// CVSSData represents CVSS v3.x score data
type CVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// CVSSDataV2 represents CVSS v2.0 score data
type CVSSDataV2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}
