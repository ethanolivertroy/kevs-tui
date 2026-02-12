package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/model"
)

const (
	kevURL  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	epssURL = "https://api.first.org/data/v1/epss"
	nvdURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// minRequestInterval limits API requests to 10/sec max to avoid rate limiting
	minRequestInterval = 100 * time.Millisecond
)

const cvssCacheTTL = 1 * time.Hour

// cvssCache provides per-CVE TTL caching for CVSS lookups
var cvssCacheMu sync.RWMutex
var cvssCacheEntries = make(map[string]cvssCacheEntry)

type cvssCacheEntry struct {
	score     model.CVSSScore
	fetchedAt time.Time
}

// Client handles API requests to the KEV data source
type Client struct {
	httpClient  *http.Client
	mu          sync.Mutex
	lastRequest time.Time
}

// NewClient creates a new API client with default settings
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// rateLimitedGet performs a rate-limited HTTP GET request
func (c *Client) rateLimitedGet(url string) (*http.Response, error) {
	c.mu.Lock()
	elapsed := time.Since(c.lastRequest)
	if elapsed < minRequestInterval {
		time.Sleep(minRequestInterval - elapsed)
	}
	c.lastRequest = time.Now()
	c.mu.Unlock()

	return c.httpClient.Get(url)
}

// FetchVulnerabilities fetches all vulnerabilities from the KEV catalog
func (c *Client) FetchVulnerabilities() ([]model.Vulnerability, error) {
	resp, err := c.rateLimitedGet(kevURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KEV data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var kevResp KEVResponse
	if err := json.NewDecoder(resp.Body).Decode(&kevResp); err != nil {
		return nil, fmt.Errorf("failed to decode KEV response: %w", err)
	}

	vulnerabilities := make([]model.Vulnerability, 0, len(kevResp.Vulnerabilities))
	for _, v := range kevResp.Vulnerabilities {
		vuln := model.Vulnerability{
			CVEID:             v.CVEID,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			ShortDescription:  v.ShortDescription,
			RequiredAction:    v.RequiredAction,
			Notes:             v.Notes,
			CWEs:              v.CWEs,
			RansomwareUse:     v.KnownRansomwareCampaignUse == "Known",
		}

		// Parse dates
		if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
			vuln.DateAdded = t
		}
		if t, err := time.Parse("2006-01-02", v.DueDate); err == nil {
			vuln.DueDate = t
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// FetchEPSSScores fetches EPSS scores for a list of CVE IDs
// Returns a map of CVE ID to EPSSScore
func (c *Client) FetchEPSSScores(cveIDs []string) (map[string]model.EPSSScore, error) {
	scores := make(map[string]model.EPSSScore)

	// EPSS API allows batch queries, but let's chunk to avoid URL length issues
	chunkSize := 100
	for i := 0; i < len(cveIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		chunk := cveIDs[i:end]

		url := fmt.Sprintf("%s?cve=%s", epssURL, strings.Join(chunk, ","))
		resp, err := c.rateLimitedGet(url)
		if err != nil {
			// Don't fail completely, just skip EPSS data
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}

		var epssResp EPSSResponse
		if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
			_ = resp.Body.Close()
			continue
		}
		_ = resp.Body.Close()

		for _, data := range epssResp.Data {
			epss, _ := strconv.ParseFloat(data.EPSS, 64)
			percentile, _ := strconv.ParseFloat(data.Percentile, 64)
			scores[data.CVE] = model.EPSSScore{
				Score:      epss,
				Percentile: percentile,
			}
		}
	}

	return scores, nil
}

// FetchCVSS fetches CVSS scores from NVD for a single CVE.
// Results are cached per CVE ID with a 1-hour TTL.
func (c *Client) FetchCVSS(cveID string) (model.CVSSScore, error) {
	// Check cache
	cvssCacheMu.RLock()
	if entry, ok := cvssCacheEntries[cveID]; ok && time.Since(entry.fetchedAt) < cvssCacheTTL {
		cvssCacheMu.RUnlock()
		return entry.score, nil
	}
	cvssCacheMu.RUnlock()

	url := fmt.Sprintf("%s?cveId=%s", nvdURL, cveID)
	resp, err := c.rateLimitedGet(url)
	if err != nil {
		return model.CVSSScore{}, fmt.Errorf("failed to fetch NVD data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return model.CVSSScore{}, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return model.CVSSScore{}, fmt.Errorf("failed to decode NVD response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return model.CVSSScore{}, fmt.Errorf("no CVE data found")
	}

	metrics := nvdResp.Vulnerabilities[0].CVE.Metrics

	var score model.CVSSScore
	var found bool

	// Prefer CVSS v3.1, then v3.0, then v2.0
	if len(metrics.CVSSMetricV31) > 0 {
		metric := metrics.CVSSMetricV31[0]
		score = model.CVSSScore{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Severity: metric.CVSSData.BaseSeverity,
			Vector:   metric.CVSSData.VectorString,
			Source:   metric.Source,
			Type:     metric.Type,
		}
		found = true
	} else if len(metrics.CVSSMetricV30) > 0 {
		metric := metrics.CVSSMetricV30[0]
		score = model.CVSSScore{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Severity: metric.CVSSData.BaseSeverity,
			Vector:   metric.CVSSData.VectorString,
			Source:   metric.Source,
			Type:     metric.Type,
		}
		found = true
	} else if len(metrics.CVSSMetricV2) > 0 {
		metric := metrics.CVSSMetricV2[0]
		score = model.CVSSScore{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Severity: metric.BaseSeverity,
			Vector:   metric.CVSSData.VectorString,
			Source:   metric.Source,
			Type:     metric.Type,
		}
		found = true
	}

	if !found {
		return model.CVSSScore{}, fmt.Errorf("no CVSS data available")
	}

	// Store in cache
	cvssCacheMu.Lock()
	cvssCacheEntries[cveID] = cvssCacheEntry{score: score, fetchedAt: time.Now()}
	cvssCacheMu.Unlock()

	return score, nil
}

// FetchCVSSAll fetches all CVSS assessments (NVD + CNA) from NVD for a single CVE
func (c *Client) FetchCVSSAll(cveID string) (model.CVSSData, error) {
	url := fmt.Sprintf("%s?cveId=%s", nvdURL, cveID)
	resp, err := c.rateLimitedGet(url)
	if err != nil {
		return model.CVSSData{}, fmt.Errorf("failed to fetch NVD data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return model.CVSSData{}, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return model.CVSSData{}, fmt.Errorf("failed to decode NVD response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return model.CVSSData{}, fmt.Errorf("no CVE data found")
	}

	metrics := nvdResp.Vulnerabilities[0].CVE.Metrics
	result := model.CVSSData{}

	// Process CVSS v3.1 metrics (preferred)
	for _, metric := range metrics.CVSSMetricV31 {
		score := model.CVSSScore{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Severity: metric.CVSSData.BaseSeverity,
			Vector:   metric.CVSSData.VectorString,
			Source:   metric.Source,
			Type:     metric.Type,
		}
		if metric.Type == "Primary" {
			result.Primary = &score
		} else {
			result.Secondary = append(result.Secondary, score)
		}
	}

	// If no v3.1, try v3.0
	if result.Primary == nil {
		for _, metric := range metrics.CVSSMetricV30 {
			score := model.CVSSScore{
				Version:  metric.CVSSData.Version,
				Score:    metric.CVSSData.BaseScore,
				Severity: metric.CVSSData.BaseSeverity,
				Vector:   metric.CVSSData.VectorString,
				Source:   metric.Source,
				Type:     metric.Type,
			}
			if metric.Type == "Primary" {
				result.Primary = &score
			} else {
				result.Secondary = append(result.Secondary, score)
			}
		}
	}

	// If still no primary, try v2.0
	if result.Primary == nil && len(metrics.CVSSMetricV2) > 0 {
		metric := metrics.CVSSMetricV2[0]
		score := model.CVSSScore{
			Version:  metric.CVSSData.Version,
			Score:    metric.CVSSData.BaseScore,
			Severity: metric.BaseSeverity,
			Vector:   metric.CVSSData.VectorString,
			Source:   metric.Source,
			Type:     metric.Type,
		}
		result.Primary = &score
	}

	return result, nil
}
