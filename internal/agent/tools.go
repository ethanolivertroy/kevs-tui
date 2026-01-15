package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/api"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
	"github.com/ethanolivertroy/kevs-tui/internal/tui"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
)

// Shared API client and cached data (protected by sync.Once for thread-safe initialization)
var (
	apiClient    *api.Client
	kevCache     []model.Vulnerability
	kevCacheOnce sync.Once
	kevCacheErr  error
)

func init() {
	apiClient = api.NewClient()
}

// getExportDir returns the safe export directory for agent-generated files
func getExportDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	exportDir := filepath.Join(homeDir, ".kevs-tui-exports")
	if err := os.MkdirAll(exportDir, 0700); err != nil {
		return "."
	}
	return exportDir
}

// ensureKEVData fetches KEV data and EPSS scores if not already cached.
// Uses sync.Once for thread-safe initialization in concurrent server mode.
func ensureKEVData() error {
	kevCacheOnce.Do(func() {
		vulns, err := apiClient.FetchVulnerabilities()
		if err != nil {
			kevCacheErr = err
			return
		}

		// Fetch EPSS scores for all CVEs
		cveIDs := make([]string, len(vulns))
		for i, v := range vulns {
			cveIDs[i] = v.CVEID
		}
		epssScores, _ := apiClient.FetchEPSSScores(cveIDs) // Ignore errors, EPSS is optional

		// Merge EPSS into vulnerabilities
		for i := range vulns {
			if score, ok := epssScores[vulns[i].CVEID]; ok {
				vulns[i].EPSS = score
			}
		}

		kevCache = vulns
	})
	return kevCacheErr
}

// --- Tool Input/Output Types ---

// SearchParams for search_kevs tool
type SearchParams struct {
	Query          string `json:"query,omitempty" jsonschema:"Search term to match against CVE ID, vendor, product, or description"`
	Vendor         string `json:"vendor,omitempty" jsonschema:"Filter by vendor/project name"`
	RansomwareOnly bool   `json:"ransomware_only,omitempty" jsonschema:"Only return CVEs with known ransomware use"`
	OverdueOnly    bool   `json:"overdue_only,omitempty" jsonschema:"Only return CVEs that are past their due date"`
	Limit          int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default 10)"`
}

// SearchResult for search_kevs tool
type SearchResult struct {
	Count   int                    `json:"count"`
	Results []VulnerabilitySummary `json:"results"`
}

// VulnerabilitySummary is a condensed view of a vulnerability
type VulnerabilitySummary struct {
	CVEID       string `json:"cve_id"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Name        string `json:"name"`
	DateAdded   string `json:"date_added"`
	DueDate     string `json:"due_date"`
	Ransomware  bool   `json:"ransomware_use"`
	IsOverdue   bool   `json:"is_overdue"`
	Description string `json:"description,omitempty"`
}

// CVEDetailsParams for get_cve_details tool
type CVEDetailsParams struct {
	CVEID string `json:"cve_id" jsonschema:"The CVE ID to look up (e.g., CVE-2024-1234)"`
}

// CVEDetailsResult for get_cve_details tool
type CVEDetailsResult struct {
	Found          bool     `json:"found"`
	CVEID          string   `json:"cve_id,omitempty"`
	Vendor         string   `json:"vendor,omitempty"`
	Product        string   `json:"product,omitempty"`
	Name           string   `json:"name,omitempty"`
	Description    string   `json:"description,omitempty"`
	DateAdded      string   `json:"date_added,omitempty"`
	DueDate        string   `json:"due_date,omitempty"`
	RequiredAction string   `json:"required_action,omitempty"`
	Ransomware     bool     `json:"ransomware_use,omitempty"`
	IsOverdue      bool     `json:"is_overdue,omitempty"`
	CWEs           []string `json:"cwes,omitempty"`
	Notes          string   `json:"notes,omitempty"`
	NVDURL         string   `json:"nvd_url,omitempty"`
	EPSSScore      float64  `json:"epss_score,omitempty"`
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
}

// ListParams for list tools
type ListParams struct {
	Limit int `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default 10)"`
}

// ListResult for list tools
type ListResult struct {
	Count   int                    `json:"count"`
	Total   int                    `json:"total"`
	Results []VulnerabilitySummary `json:"results"`
}

// StatsParams for get_stats tool
type StatsParams struct {
	TopN int `json:"top_n,omitempty" jsonschema:"Number of top items to return for vendor/CWE breakdowns (default 10)"`
}

// StatsResult for get_stats tool
type StatsResult struct {
	TotalCVEs       int           `json:"total_cves"`
	RansomwareCount int           `json:"ransomware_count"`
	OverdueCount    int           `json:"overdue_count"`
	TopVendors      []VendorCount `json:"top_vendors"`
	TopCWEs         []CWECount    `json:"top_cwes"`
	RiskBreakdown   RiskBreakdown `json:"risk_breakdown"`
}

// VendorCount for stats
type VendorCount struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"`
}

// CWECount for stats
type CWECount struct {
	CWE   string `json:"cwe"`
	Count int    `json:"count"`
}

// RiskBreakdown for stats
type RiskBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ExportParams for export_report tool
type ExportParams struct {
	Format string `json:"format" jsonschema:"Export format: json, csv, or markdown"`
	Query  string `json:"query,omitempty" jsonschema:"Optional search filter to apply before export"`
}

// ExportResult for export_report tool
type ExportResult struct {
	Success  bool   `json:"success"`
	FilePath string `json:"file_path,omitempty"`
	Count    int    `json:"count,omitempty"`
	Error    string `json:"error,omitempty"`
}

// --- Tool Implementations ---

func searchKEVs(ctx tool.Context, params SearchParams) (SearchResult, error) {
	if err := ensureKEVData(); err != nil {
		return SearchResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	var results []VulnerabilitySummary
	query := strings.ToLower(params.Query)
	vendor := strings.ToLower(params.Vendor)

	for _, v := range kevCache {
		// Filter by vendor if specified
		if vendor != "" && !strings.Contains(strings.ToLower(v.VendorProject), vendor) {
			continue
		}

		// Filter by ransomware if specified
		if params.RansomwareOnly && !v.RansomwareUse {
			continue
		}

		// Filter by overdue if specified
		if params.OverdueOnly && !v.IsOverdue() {
			continue
		}

		// Match query against multiple fields
		if query != "" {
			match := strings.Contains(strings.ToLower(v.CVEID), query) ||
				strings.Contains(strings.ToLower(v.VendorProject), query) ||
				strings.Contains(strings.ToLower(v.Product), query) ||
				strings.Contains(strings.ToLower(v.VulnerabilityName), query) ||
				strings.Contains(strings.ToLower(v.ShortDescription), query)
			if !match {
				continue
			}
		}

		results = append(results, VulnerabilitySummary{
			CVEID:      v.CVEID,
			Vendor:     v.VendorProject,
			Product:    v.Product,
			Name:       v.VulnerabilityName,
			DateAdded:  v.DateAdded.Format("2006-01-02"),
			DueDate:    v.DueDate.Format("2006-01-02"),
			Ransomware: v.RansomwareUse,
			IsOverdue:  v.IsOverdue(),
		})

		if len(results) >= limit {
			break
		}
	}

	return SearchResult{
		Count:   len(results),
		Results: results,
	}, nil
}

func getCVEDetails(ctx tool.Context, params CVEDetailsParams) (CVEDetailsResult, error) {
	if err := ensureKEVData(); err != nil {
		return CVEDetailsResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	cveID := strings.ToUpper(params.CVEID)
	for _, v := range kevCache {
		if v.CVEID == cveID {
			return CVEDetailsResult{
				Found:          true,
				CVEID:          v.CVEID,
				Vendor:         v.VendorProject,
				Product:        v.Product,
				Name:           v.VulnerabilityName,
				Description:    v.ShortDescription,
				DateAdded:      v.DateAdded.Format("2006-01-02"),
				DueDate:        v.DueDate.Format("2006-01-02"),
				RequiredAction: v.RequiredAction,
				Ransomware:     v.RansomwareUse,
				IsOverdue:      v.IsOverdue(),
				CWEs:           v.CWEs,
				Notes:          v.Notes,
				NVDURL:         v.NVDURL(),
				EPSSScore:      v.EPSS.Score,
				EPSSPercentile: v.EPSS.Percentile,
			}, nil
		}
	}

	return CVEDetailsResult{Found: false}, nil
}

func listRansomwareCVEs(ctx tool.Context, params ListParams) (ListResult, error) {
	if err := ensureKEVData(); err != nil {
		return ListResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	var results []VulnerabilitySummary
	total := 0

	for _, v := range kevCache {
		if v.RansomwareUse {
			total++
			if len(results) < limit {
				results = append(results, VulnerabilitySummary{
					CVEID:      v.CVEID,
					Vendor:     v.VendorProject,
					Product:    v.Product,
					Name:       v.VulnerabilityName,
					DateAdded:  v.DateAdded.Format("2006-01-02"),
					DueDate:    v.DueDate.Format("2006-01-02"),
					Ransomware: true,
					IsOverdue:  v.IsOverdue(),
				})
			}
		}
	}

	return ListResult{
		Count:   len(results),
		Total:   total,
		Results: results,
	}, nil
}

func listOverdueCVEs(ctx tool.Context, params ListParams) (ListResult, error) {
	if err := ensureKEVData(); err != nil {
		return ListResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	var results []VulnerabilitySummary
	total := 0
	now := time.Now()

	for _, v := range kevCache {
		if !v.DueDate.IsZero() && v.DueDate.Before(now) {
			total++
			if len(results) < limit {
				results = append(results, VulnerabilitySummary{
					CVEID:      v.CVEID,
					Vendor:     v.VendorProject,
					Product:    v.Product,
					Name:       v.VulnerabilityName,
					DateAdded:  v.DateAdded.Format("2006-01-02"),
					DueDate:    v.DueDate.Format("2006-01-02"),
					Ransomware: v.RansomwareUse,
					IsOverdue:  true,
				})
			}
		}
	}

	return ListResult{
		Count:   len(results),
		Total:   total,
		Results: results,
	}, nil
}

func getStats(ctx tool.Context, params StatsParams) (StatsResult, error) {
	if err := ensureKEVData(); err != nil {
		return StatsResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	topN := params.TopN
	if topN <= 0 {
		topN = 10
	}

	// Get vendor stats using existing chart functions
	vendorStats := tui.GetTopVendors(kevCache, topN)
	var topVendors []VendorCount
	for _, vs := range vendorStats {
		topVendors = append(topVendors, VendorCount{
			Vendor: vs.Name,
			Count:  vs.Count,
		})
	}

	// Get CWE stats
	cweStats := tui.GetTopCWEs(kevCache, topN)
	var topCWEs []CWECount
	for _, cs := range cweStats {
		topCWEs = append(topCWEs, CWECount{
			CWE:   cs.ID,
			Count: cs.Count,
		})
	}

	// Get risk stats
	riskStats := tui.GetRiskStats(kevCache)

	// Get ransomware stats
	ransomwareStats := tui.GetRansomwareStats(kevCache)

	// Count overdue
	overdueCount := 0
	now := time.Now()
	for _, v := range kevCache {
		if !v.DueDate.IsZero() && v.DueDate.Before(now) {
			overdueCount++
		}
	}

	return StatsResult{
		TotalCVEs:       len(kevCache),
		RansomwareCount: ransomwareStats.Known,
		OverdueCount:    overdueCount,
		TopVendors:      topVendors,
		TopCWEs:         topCWEs,
		RiskBreakdown: RiskBreakdown{
			Critical: riskStats.Critical,
			High:     riskStats.High,
			Medium:   riskStats.Medium,
			Low:      riskStats.Low,
		},
	}, nil
}

func exportReport(ctx tool.Context, params ExportParams) (ExportResult, error) {
	if err := ensureKEVData(); err != nil {
		return ExportResult{Success: false, Error: err.Error()}, nil
	}

	// Determine format
	var format tui.ExportFormat
	switch strings.ToLower(params.Format) {
	case "json":
		format = tui.ExportJSON
	case "csv":
		format = tui.ExportCSV
	case "markdown", "md":
		format = tui.ExportMarkdown
	default:
		return ExportResult{Success: false, Error: "invalid format, use json, csv, or markdown"}, nil
	}

	// Filter if query provided
	vulns := kevCache
	if params.Query != "" {
		query := strings.ToLower(params.Query)
		var filtered []model.Vulnerability
		for _, v := range kevCache {
			match := strings.Contains(strings.ToLower(v.CVEID), query) ||
				strings.Contains(strings.ToLower(v.VendorProject), query) ||
				strings.Contains(strings.ToLower(v.Product), query) ||
				strings.Contains(strings.ToLower(v.ShortDescription), query)
			if match {
				filtered = append(filtered, v)
			}
		}
		vulns = filtered
	}

	// Use safe export directory (not current working directory)
	outputDir := getExportDir()

	result := tui.Export(vulns, format, outputDir)
	if result.Err != nil {
		return ExportResult{Success: false, Error: result.Err.Error()}, nil
	}

	return ExportResult{
		Success:  true,
		FilePath: result.FilePath,
		Count:    result.Count,
	}, nil
}

// CreateTools creates all KEV tools for the agent
func CreateTools() ([]tool.Tool, error) {
	searchTool, err := functiontool.New(
		functiontool.Config{
			Name:        "search_kevs",
			Description: "Search the CISA Known Exploited Vulnerabilities catalog by keyword, vendor, or product name",
		},
		searchKEVs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create search_kevs tool: %w", err)
	}

	detailsTool, err := functiontool.New(
		functiontool.Config{
			Name:        "get_cve_details",
			Description: "Get detailed information about a specific CVE from the KEV catalog",
		},
		getCVEDetails,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_cve_details tool: %w", err)
	}

	ransomwareTool, err := functiontool.New(
		functiontool.Config{
			Name:        "list_ransomware_cves",
			Description: "List CVEs that are known to be used in ransomware campaigns",
		},
		listRansomwareCVEs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create list_ransomware_cves tool: %w", err)
	}

	overdueTool, err := functiontool.New(
		functiontool.Config{
			Name:        "list_overdue_cves",
			Description: "List CVEs that are past their remediation due date",
		},
		listOverdueCVEs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create list_overdue_cves tool: %w", err)
	}

	statsTool, err := functiontool.New(
		functiontool.Config{
			Name:        "get_stats",
			Description: "Get summary statistics about the KEV catalog including totals, top vendors, top CWEs, and risk breakdown",
		},
		getStats,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_stats tool: %w", err)
	}

	exportTool, err := functiontool.New(
		functiontool.Config{
			Name:        "export_report",
			Description: "Export KEV data to a file in JSON, CSV, or Markdown format",
		},
		exportReport,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create export_report tool: %w", err)
	}

	return []tool.Tool{
		searchTool,
		detailsTool,
		ransomwareTool,
		overdueTool,
		statsTool,
		exportTool,
	}, nil
}
