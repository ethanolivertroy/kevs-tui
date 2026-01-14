package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/model"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
)

// cveIDRegex validates CVE ID format (CVE-YYYY-NNNNN)
var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Risk score calculation constants
const (
	// Vendor risk score weights
	RiskScoreBaseCVEWeight    = 2.0  // Points per CVE
	RiskScoreBaseCap          = 30.0 // Max points from CVE count
	RiskScoreRansomwareWeight = 5.0  // Points per ransomware CVE
	RiskScoreRansomwareCap    = 25.0 // Max points from ransomware
	RiskScoreOverdueWeight    = 3.0  // Points per overdue CVE
	RiskScoreOverdueCap       = 25.0 // Max points from overdue
	RiskScoreEPSSWeight       = 20.0 // EPSS multiplier (0-1 -> 0-20)
	RiskScoreMaxTotal         = 100.0

	// Risk priority weights
	RiskPriorityEPSSWeight      = 40.0 // EPSS multiplier for priority
	RiskPriorityRansomwareBonus = 30.0 // Bonus for ransomware association
	RiskPriorityOverdueBonus    = 20.0 // Bonus for overdue status

	// Risk level thresholds
	RiskLevelCriticalThreshold = 75.0
	RiskLevelHighThreshold     = 50.0
	RiskLevelMediumThreshold   = 25.0

	// Risk priority thresholds
	RiskPriorityCriticalThreshold = 70.0
	RiskPriorityHighThreshold     = 50.0
	RiskPriorityMediumThreshold   = 25.0
)

// validateCVEID validates and normalizes a CVE ID
func validateCVEID(input string) (string, error) {
	cveID := strings.ToUpper(strings.TrimSpace(input))
	if cveID == "" {
		return "", fmt.Errorf("CVE ID is required")
	}
	if !cveIDRegex.MatchString(cveID) {
		return "", fmt.Errorf("invalid CVE ID format: %s (expected CVE-YYYY-NNNNN)", input)
	}
	return cveID, nil
}

// --- Related CVEs Tool ---

// RelatedCVEsParams for find_related_cves tool
type RelatedCVEsParams struct {
	CVEID   string `json:"cve_id,omitempty" jsonschema:"Find CVEs related to this CVE ID"`
	CWE     string `json:"cwe,omitempty" jsonschema:"Find CVEs with this CWE (e.g., CWE-79 or just 79)"`
	Vendor  string `json:"vendor,omitempty" jsonschema:"Find CVEs from this vendor"`
	Product string `json:"product,omitempty" jsonschema:"Find CVEs affecting this product"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum results (default 10)"`
}

// RelatedCVEsResult for find_related_cves tool
type RelatedCVEsResult struct {
	Query        string           `json:"query_description"`
	Count        int              `json:"count"`
	RelatedCVEs  []RelatedCVEItem `json:"related_cves"`
	CommonCWEs   []string         `json:"common_cwes,omitempty"`
	CommonVendor string           `json:"common_vendor,omitempty"`
}

// RelatedCVEItem represents a related CVE with similarity info
type RelatedCVEItem struct {
	CVEID      string   `json:"cve_id"`
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	Name       string   `json:"name"`
	Similarity string   `json:"similarity_reason"`
	CWEs       []string `json:"cwes,omitempty"`
	EPSSScore  float64  `json:"epss_score"`
	IsOverdue  bool     `json:"is_overdue"`
	Ransomware bool     `json:"ransomware_use"`
}

func findRelatedCVEs(ctx tool.Context, params RelatedCVEsParams) (RelatedCVEsResult, error) {
	if err := ensureKEVData(); err != nil {
		return RelatedCVEsResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	var results []RelatedCVEItem
	var queryDesc string
	var sourceCWEs []string
	var sourceVendor, sourceProduct string
	var sourceCVEID string // Validated CVE ID to exclude from results

	// If CVE ID provided, find it first to get its attributes
	if params.CVEID != "" {
		cveID, err := validateCVEID(params.CVEID)
		if err != nil {
			return RelatedCVEsResult{}, err
		}
		sourceCVEID = cveID
		for _, v := range kevCache {
			if v.CVEID == cveID {
				sourceCWEs = v.CWEs
				sourceVendor = v.VendorProject
				sourceProduct = v.Product
				queryDesc = fmt.Sprintf("CVEs related to %s (%s %s)", cveID, sourceVendor, sourceProduct)
				break
			}
		}
		if sourceVendor == "" {
			return RelatedCVEsResult{Query: fmt.Sprintf("CVE %s not found", cveID)}, nil
		}
	}

	// Build query description if not from CVE
	if queryDesc == "" {
		parts := []string{}
		if params.CWE != "" {
			parts = append(parts, fmt.Sprintf("CWE: %s", normalizeCWE(params.CWE)))
		}
		if params.Vendor != "" {
			parts = append(parts, fmt.Sprintf("Vendor: %s", params.Vendor))
			sourceVendor = params.Vendor
		}
		if params.Product != "" {
			parts = append(parts, fmt.Sprintf("Product: %s", params.Product))
			sourceProduct = params.Product
		}
		queryDesc = "CVEs matching: " + strings.Join(parts, ", ")
	}

	// Normalize CWE input
	targetCWE := normalizeCWE(params.CWE)
	if len(sourceCWEs) > 0 && targetCWE == "" {
		// Use CWEs from source CVE
		for _, cwe := range sourceCWEs {
			targetCWE = normalizeCWE(cwe)
			break // Use first CWE
		}
	}

	// Find related CVEs
	for _, v := range kevCache {
		// Skip the source CVE itself
		if sourceCVEID != "" && v.CVEID == sourceCVEID {
			continue
		}

		var reasons []string

		// Match by CWE
		if targetCWE != "" {
			for _, cwe := range v.CWEs {
				if normalizeCWE(cwe) == targetCWE {
					reasons = append(reasons, fmt.Sprintf("Same CWE (%s)", targetCWE))
					break
				}
			}
		}

		// Match by vendor
		if sourceVendor != "" && strings.EqualFold(v.VendorProject, sourceVendor) {
			reasons = append(reasons, "Same vendor")
		}

		// Match by product
		if sourceProduct != "" && strings.EqualFold(v.Product, sourceProduct) {
			reasons = append(reasons, "Same product")
		}

		// Match by explicit params
		if params.Vendor != "" && strings.Contains(strings.ToLower(v.VendorProject), strings.ToLower(params.Vendor)) {
			if !contains(reasons, "Same vendor") {
				reasons = append(reasons, "Matching vendor")
			}
		}
		if params.Product != "" && strings.Contains(strings.ToLower(v.Product), strings.ToLower(params.Product)) {
			if !contains(reasons, "Same product") {
				reasons = append(reasons, "Matching product")
			}
		}

		if len(reasons) > 0 {
			results = append(results, RelatedCVEItem{
				CVEID:      v.CVEID,
				Vendor:     v.VendorProject,
				Product:    v.Product,
				Name:       v.VulnerabilityName,
				Similarity: strings.Join(reasons, ", "),
				CWEs:       v.CWEs,
				EPSSScore:  v.EPSS.Score,
				IsOverdue:  v.IsOverdue(),
				Ransomware: v.RansomwareUse,
			})
		}
	}

	// Sort by EPSS score (highest risk first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].EPSSScore > results[j].EPSSScore
	})

	// Limit results
	if len(results) > limit {
		results = results[:limit]
	}

	return RelatedCVEsResult{
		Query:        queryDesc,
		Count:        len(results),
		RelatedCVEs:  results,
		CommonCWEs:   sourceCWEs,
		CommonVendor: sourceVendor,
	}, nil
}

// --- Vendor Risk Profile Tool ---

// VendorRiskParams for get_vendor_risk_profile tool
type VendorRiskParams struct {
	Vendor string `json:"vendor" jsonschema:"Vendor name to analyze"`
}

// VendorRiskResult for get_vendor_risk_profile tool
type VendorRiskResult struct {
	Vendor          string                 `json:"vendor"`
	Found           bool                   `json:"found"`
	TotalCVEs       int                    `json:"total_cves"`
	RansomwareCVEs  int                    `json:"ransomware_cves"`
	OverdueCVEs     int                    `json:"overdue_cves"`
	AverageEPSS     float64                `json:"average_epss"`
	MaxEPSS         float64                `json:"max_epss"`
	RiskScore       float64                `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level"`
	TopProducts     []ProductRiskCount     `json:"top_products"`
	TopCWEs         []string               `json:"top_cwes"`
	RecentCVEs      []VulnerabilitySummary `json:"recent_cves"`
	OldestUnpatched string                 `json:"oldest_unpatched,omitempty"`
}

// ProductRiskCount for vendor risk analysis
type ProductRiskCount struct {
	Product       string  `json:"product"`
	CVECount      int     `json:"cve_count"`
	RansomwareUse int     `json:"ransomware_count"`
	AvgEPSS       float64 `json:"avg_epss"`
}

func getVendorRiskProfile(ctx tool.Context, params VendorRiskParams) (VendorRiskResult, error) {
	if err := ensureKEVData(); err != nil {
		return VendorRiskResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	vendor := strings.ToLower(params.Vendor)
	if vendor == "" {
		return VendorRiskResult{Found: false}, nil
	}

	var matchingCVEs []struct {
		cve     VulnerabilitySummary
		epss    float64
		ransom  bool
		overdue bool
		product string
		cwes    []string
		added   time.Time
	}

	productStats := make(map[string]*ProductRiskCount)
	cweCount := make(map[string]int)

	for _, v := range kevCache {
		if !strings.Contains(strings.ToLower(v.VendorProject), vendor) {
			continue
		}

		isOverdue := v.IsOverdue()
		matchingCVEs = append(matchingCVEs, struct {
			cve     VulnerabilitySummary
			epss    float64
			ransom  bool
			overdue bool
			product string
			cwes    []string
			added   time.Time
		}{
			cve: VulnerabilitySummary{
				CVEID:      v.CVEID,
				Vendor:     v.VendorProject,
				Product:    v.Product,
				Name:       v.VulnerabilityName,
				DateAdded:  v.DateAdded.Format("2006-01-02"),
				DueDate:    v.DueDate.Format("2006-01-02"),
				Ransomware: v.RansomwareUse,
				IsOverdue:  isOverdue,
			},
			epss:    v.EPSS.Score,
			ransom:  v.RansomwareUse,
			overdue: isOverdue,
			product: v.Product,
			cwes:    v.CWEs,
			added:   v.DateAdded,
		})

		// Product stats
		if _, ok := productStats[v.Product]; !ok {
			productStats[v.Product] = &ProductRiskCount{Product: v.Product}
		}
		productStats[v.Product].CVECount++
		if v.RansomwareUse {
			productStats[v.Product].RansomwareUse++
		}
		productStats[v.Product].AvgEPSS += v.EPSS.Score

		// CWE stats
		for _, cwe := range v.CWEs {
			cweCount[cwe]++
		}
	}

	if len(matchingCVEs) == 0 {
		return VendorRiskResult{
			Vendor: params.Vendor,
			Found:  false,
		}, nil
	}

	// Calculate averages
	var totalEPSS, maxEPSS float64
	var ransomCount, overdueCount int
	var oldestOverdue time.Time

	for _, m := range matchingCVEs {
		totalEPSS += m.epss
		if m.epss > maxEPSS {
			maxEPSS = m.epss
		}
		if m.ransom {
			ransomCount++
		}
		if m.overdue {
			overdueCount++
			if oldestOverdue.IsZero() || m.added.Before(oldestOverdue) {
				oldestOverdue = m.added
			}
		}
	}

	avgEPSS := totalEPSS / float64(len(matchingCVEs))

	// Finalize product averages
	for _, ps := range productStats {
		if ps.CVECount > 0 {
			ps.AvgEPSS /= float64(ps.CVECount)
		}
	}

	// Sort products by CVE count
	var topProducts []ProductRiskCount
	for _, ps := range productStats {
		topProducts = append(topProducts, *ps)
	}
	sort.Slice(topProducts, func(i, j int) bool {
		return topProducts[i].CVECount > topProducts[j].CVECount
	})
	if len(topProducts) > 5 {
		topProducts = topProducts[:5]
	}

	// Sort CWEs by count
	var topCWEs []string
	type cweStat struct {
		cwe   string
		count int
	}
	var cweStats []cweStat
	for cwe, count := range cweCount {
		cweStats = append(cweStats, cweStat{cwe, count})
	}
	sort.Slice(cweStats, func(i, j int) bool {
		return cweStats[i].count > cweStats[j].count
	})
	for i := 0; i < len(cweStats) && i < 5; i++ {
		topCWEs = append(topCWEs, cweStats[i].cwe)
	}

	// Get most recent CVEs
	sort.Slice(matchingCVEs, func(i, j int) bool {
		return matchingCVEs[i].added.After(matchingCVEs[j].added)
	})
	var recentCVEs []VulnerabilitySummary
	for i := 0; i < len(matchingCVEs) && i < 5; i++ {
		recentCVEs = append(recentCVEs, matchingCVEs[i].cve)
	}

	// Calculate risk score (0-100)
	riskScore := calculateVendorRiskScore(len(matchingCVEs), ransomCount, overdueCount, avgEPSS)
	riskLevel := getRiskLevel(riskScore)

	result := VendorRiskResult{
		Vendor:         params.Vendor,
		Found:          true,
		TotalCVEs:      len(matchingCVEs),
		RansomwareCVEs: ransomCount,
		OverdueCVEs:    overdueCount,
		AverageEPSS:    avgEPSS,
		MaxEPSS:        maxEPSS,
		RiskScore:      riskScore,
		RiskLevel:      riskLevel,
		TopProducts:    topProducts,
		TopCWEs:        topCWEs,
		RecentCVEs:     recentCVEs,
	}

	if !oldestOverdue.IsZero() {
		result.OldestUnpatched = oldestOverdue.Format("2006-01-02")
	}

	return result, nil
}

// --- Batch Analyze Tool ---

// BatchAnalyzeParams for batch_analyze tool
type BatchAnalyzeParams struct {
	CVEIDs []string `json:"cve_ids" jsonschema:"List of CVE IDs to analyze"`
}

// BatchAnalyzeResult for batch_analyze tool
type BatchAnalyzeResult struct {
	Count    int                `json:"count"`
	Found    int                `json:"found"`
	NotFound []string           `json:"not_found,omitempty"`
	CVEs     []BatchCVEAnalysis `json:"cves"`
	Summary  BatchSummary       `json:"summary"`
}

// BatchCVEAnalysis is detailed analysis for one CVE
type BatchCVEAnalysis struct {
	CVEID          string   `json:"cve_id"`
	Found          bool     `json:"found"`
	Vendor         string   `json:"vendor,omitempty"`
	Product        string   `json:"product,omitempty"`
	Name           string   `json:"name,omitempty"`
	EPSSScore      float64  `json:"epss_score"`
	EPSSPercentile float64  `json:"epss_percentile"`
	IsOverdue      bool     `json:"is_overdue"`
	DaysOverdue    int      `json:"days_overdue,omitempty"`
	Ransomware     bool     `json:"ransomware_use"`
	CWEs           []string `json:"cwes,omitempty"`
	RiskPriority   string   `json:"risk_priority"`
}

// BatchSummary provides aggregate stats
type BatchSummary struct {
	TotalAnalyzed   int      `json:"total_analyzed"`
	OverdueCount    int      `json:"overdue_count"`
	RansomwareCount int      `json:"ransomware_count"`
	AvgEPSS         float64  `json:"avg_epss"`
	MaxEPSS         float64  `json:"max_epss"`
	CriticalCount   int      `json:"critical_priority"`
	HighCount       int      `json:"high_priority"`
	MediumCount     int      `json:"medium_priority"`
	LowCount        int      `json:"low_priority"`
	CommonVendors   []string `json:"common_vendors"`
	CommonCWEs      []string `json:"common_cwes"`
}

func batchAnalyze(ctx tool.Context, params BatchAnalyzeParams) (BatchAnalyzeResult, error) {
	if err := ensureKEVData(); err != nil {
		return BatchAnalyzeResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	if len(params.CVEIDs) == 0 {
		return BatchAnalyzeResult{}, fmt.Errorf("no CVE IDs provided")
	}

	// Build lookup map for O(1) lookups
	cveMap := make(map[string]model.Vulnerability)
	for _, v := range kevCache {
		cveMap[v.CVEID] = v
	}

	var analyses []BatchCVEAnalysis
	var notFound []string
	var invalidIDs []string
	vendorCount := make(map[string]int)
	cweCount := make(map[string]int)
	var totalEPSS, maxEPSS float64
	var overdueCount, ransomwareCount int
	var criticalCount, highCount, mediumCount, lowCount int

	for _, rawCVEID := range params.CVEIDs {
		cveID, err := validateCVEID(rawCVEID)
		if err != nil {
			invalidIDs = append(invalidIDs, rawCVEID)
			continue
		}

		v, found := cveMap[cveID]
		if found {
			daysOverdue := 0
			if v.IsOverdue() {
				daysOverdue = int(time.Since(v.DueDate).Hours() / 24)
				overdueCount++
			}
			if v.RansomwareUse {
				ransomwareCount++
			}

			priority := calculateRiskPriority(v.EPSS.Score, v.IsOverdue(), v.RansomwareUse)
			switch priority {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}

			totalEPSS += v.EPSS.Score
			if v.EPSS.Score > maxEPSS {
				maxEPSS = v.EPSS.Score
			}

			vendorCount[v.VendorProject]++
			for _, cwe := range v.CWEs {
				cweCount[cwe]++
			}

			analyses = append(analyses, BatchCVEAnalysis{
				CVEID:          v.CVEID,
				Found:          true,
				Vendor:         v.VendorProject,
				Product:        v.Product,
				Name:           v.VulnerabilityName,
				EPSSScore:      v.EPSS.Score,
				EPSSPercentile: v.EPSS.Percentile,
				IsOverdue:      v.IsOverdue(),
				DaysOverdue:    daysOverdue,
				Ransomware:     v.RansomwareUse,
				CWEs:           v.CWEs,
				RiskPriority:   priority,
			})
		} else {
			notFound = append(notFound, cveID)
			analyses = append(analyses, BatchCVEAnalysis{
				CVEID: cveID,
				Found: false,
			})
		}
	}

	// Sort analyses by risk priority
	priorityOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.Slice(analyses, func(i, j int) bool {
		if !analyses[i].Found {
			return false
		}
		if !analyses[j].Found {
			return true
		}
		return priorityOrder[analyses[i].RiskPriority] < priorityOrder[analyses[j].RiskPriority]
	})

	// Get top vendors
	var commonVendors []string
	type vendorStat struct {
		vendor string
		count  int
	}
	var vendorStats []vendorStat
	for v, c := range vendorCount {
		vendorStats = append(vendorStats, vendorStat{v, c})
	}
	sort.Slice(vendorStats, func(i, j int) bool {
		return vendorStats[i].count > vendorStats[j].count
	})
	for i := 0; i < len(vendorStats) && i < 3; i++ {
		commonVendors = append(commonVendors, vendorStats[i].vendor)
	}

	// Get top CWEs
	var commonCWEs []string
	type cweStat struct {
		cwe   string
		count int
	}
	var cweStats []cweStat
	for c, cnt := range cweCount {
		cweStats = append(cweStats, cweStat{c, cnt})
	}
	sort.Slice(cweStats, func(i, j int) bool {
		return cweStats[i].count > cweStats[j].count
	})
	for i := 0; i < len(cweStats) && i < 3; i++ {
		commonCWEs = append(commonCWEs, cweStats[i].cwe)
	}

	foundCount := len(params.CVEIDs) - len(notFound)
	avgEPSS := 0.0
	if foundCount > 0 {
		avgEPSS = totalEPSS / float64(foundCount)
	}

	return BatchAnalyzeResult{
		Count:    len(params.CVEIDs),
		Found:    foundCount,
		NotFound: notFound,
		CVEs:     analyses,
		Summary: BatchSummary{
			TotalAnalyzed:   foundCount,
			OverdueCount:    overdueCount,
			RansomwareCount: ransomwareCount,
			AvgEPSS:         avgEPSS,
			MaxEPSS:         maxEPSS,
			CriticalCount:   criticalCount,
			HighCount:       highCount,
			MediumCount:     mediumCount,
			LowCount:        lowCount,
			CommonVendors:   commonVendors,
			CommonCWEs:      commonCWEs,
		},
	}, nil
}

// --- CWE Analysis Tool ---

// AnalyzeCWEParams for analyze_cwe tool
type AnalyzeCWEParams struct {
	CWE   string `json:"cwe" jsonschema:"CWE ID to analyze (e.g., CWE-79 or just 79)"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum CVEs to return (default 10)"`
}

// AnalyzeCWEResult for analyze_cwe tool
type AnalyzeCWEResult struct {
	CWE              string                 `json:"cwe"`
	CWEName          string                 `json:"cwe_name,omitempty"`
	Found            bool                   `json:"found"`
	TotalCVEs        int                    `json:"total_cves"`
	RansomwareCVEs   int                    `json:"ransomware_cves"`
	OverdueCVEs      int                    `json:"overdue_cves"`
	AverageEPSS      float64                `json:"average_epss"`
	AffectedVendors  []VendorCount          `json:"affected_vendors"`
	AffectedProducts []string               `json:"affected_products"`
	CVEs             []VulnerabilitySummary `json:"cves"`
	Mitigations      []string               `json:"suggested_mitigations,omitempty"`
}

func analyzeCWE(ctx tool.Context, params AnalyzeCWEParams) (AnalyzeCWEResult, error) {
	if err := ensureKEVData(); err != nil {
		return AnalyzeCWEResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	targetCWE := normalizeCWE(params.CWE)
	if targetCWE == "" {
		return AnalyzeCWEResult{Found: false}, fmt.Errorf("invalid CWE format")
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	var matchingCVEs []VulnerabilitySummary
	vendorCount := make(map[string]int)
	productSet := make(map[string]bool)
	var totalEPSS float64
	var ransomwareCount, overdueCount int

	for _, v := range kevCache {
		for _, cwe := range v.CWEs {
			if normalizeCWE(cwe) == targetCWE {
				matchingCVEs = append(matchingCVEs, VulnerabilitySummary{
					CVEID:      v.CVEID,
					Vendor:     v.VendorProject,
					Product:    v.Product,
					Name:       v.VulnerabilityName,
					DateAdded:  v.DateAdded.Format("2006-01-02"),
					DueDate:    v.DueDate.Format("2006-01-02"),
					Ransomware: v.RansomwareUse,
					IsOverdue:  v.IsOverdue(),
				})

				vendorCount[v.VendorProject]++
				productSet[v.Product] = true
				totalEPSS += v.EPSS.Score

				if v.RansomwareUse {
					ransomwareCount++
				}
				if v.IsOverdue() {
					overdueCount++
				}
				break
			}
		}
	}

	if len(matchingCVEs) == 0 {
		return AnalyzeCWEResult{
			CWE:   targetCWE,
			Found: false,
		}, nil
	}

	// Sort vendors by count
	var affectedVendors []VendorCount
	for v, c := range vendorCount {
		affectedVendors = append(affectedVendors, VendorCount{Vendor: v, Count: c})
	}
	sort.Slice(affectedVendors, func(i, j int) bool {
		return affectedVendors[i].Count > affectedVendors[j].Count
	})
	if len(affectedVendors) > 10 {
		affectedVendors = affectedVendors[:10]
	}

	// Get products
	var affectedProducts []string
	for p := range productSet {
		affectedProducts = append(affectedProducts, p)
	}
	sort.Strings(affectedProducts)
	if len(affectedProducts) > 10 {
		affectedProducts = affectedProducts[:10]
	}

	// Limit CVEs
	if len(matchingCVEs) > limit {
		matchingCVEs = matchingCVEs[:limit]
	}

	avgEPSS := totalEPSS / float64(len(matchingCVEs))

	// Get CWE name and mitigations
	cweName, mitigations := getCWEInfo(targetCWE)

	return AnalyzeCWEResult{
		CWE:              targetCWE,
		CWEName:          cweName,
		Found:            true,
		TotalCVEs:        len(matchingCVEs),
		RansomwareCVEs:   ransomwareCount,
		OverdueCVEs:      overdueCount,
		AverageEPSS:      avgEPSS,
		AffectedVendors:  affectedVendors,
		AffectedProducts: affectedProducts,
		CVEs:             matchingCVEs,
		Mitigations:      mitigations,
	}, nil
}

// --- Helper Functions ---

func normalizeCWE(cwe string) string {
	cwe = strings.TrimSpace(strings.ToUpper(cwe))
	cwe = strings.TrimPrefix(cwe, "CWE-")
	if cwe == "" {
		return ""
	}
	return "CWE-" + cwe
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func calculateVendorRiskScore(totalCVEs, ransomwareCVEs, overdueCVEs int, avgEPSS float64) float64 {
	// Base score from CVE count
	baseScore := float64(totalCVEs) * RiskScoreBaseCVEWeight
	if baseScore > RiskScoreBaseCap {
		baseScore = RiskScoreBaseCap
	}

	// Ransomware penalty
	ransomwareScore := float64(ransomwareCVEs) * RiskScoreRansomwareWeight
	if ransomwareScore > RiskScoreRansomwareCap {
		ransomwareScore = RiskScoreRansomwareCap
	}

	// Overdue penalty
	overdueScore := float64(overdueCVEs) * RiskScoreOverdueWeight
	if overdueScore > RiskScoreOverdueCap {
		overdueScore = RiskScoreOverdueCap
	}

	// EPSS score
	epssScore := avgEPSS * RiskScoreEPSSWeight

	total := baseScore + ransomwareScore + overdueScore + epssScore
	if total > RiskScoreMaxTotal {
		total = RiskScoreMaxTotal
	}

	return total
}

func getRiskLevel(score float64) string {
	switch {
	case score >= RiskLevelCriticalThreshold:
		return "CRITICAL"
	case score >= RiskLevelHighThreshold:
		return "HIGH"
	case score >= RiskLevelMediumThreshold:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func calculateRiskPriority(epss float64, isOverdue, isRansomware bool) string {
	score := epss * RiskPriorityEPSSWeight

	if isRansomware {
		score += RiskPriorityRansomwareBonus
	}
	if isOverdue {
		score += RiskPriorityOverdueBonus
	}

	switch {
	case score >= RiskPriorityCriticalThreshold:
		return "CRITICAL"
	case score >= RiskPriorityHighThreshold:
		return "HIGH"
	case score >= RiskPriorityMediumThreshold:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func getCWEInfo(cwe string) (name string, mitigations []string) {
	// Common CWE names and mitigations
	cweData := map[string]struct {
		name        string
		mitigations []string
	}{
		"CWE-78": {
			"OS Command Injection",
			[]string{"Input validation", "Use parameterized commands", "Avoid shell execution", "Principle of least privilege"},
		},
		"CWE-79": {
			"Cross-site Scripting (XSS)",
			[]string{"Output encoding", "Content Security Policy", "Input validation", "Use modern frameworks with auto-escaping"},
		},
		"CWE-89": {
			"SQL Injection",
			[]string{"Parameterized queries", "Stored procedures", "Input validation", "Least privilege database accounts"},
		},
		"CWE-94": {
			"Code Injection",
			[]string{"Input validation", "Avoid dynamic code execution", "Sandboxing", "Code review"},
		},
		"CWE-119": {
			"Buffer Overflow",
			[]string{"Bounds checking", "Use safe functions", "ASLR/DEP", "Memory-safe languages"},
		},
		"CWE-200": {
			"Information Exposure",
			[]string{"Access controls", "Data classification", "Encryption", "Audit logging"},
		},
		"CWE-269": {
			"Improper Privilege Management",
			[]string{"Principle of least privilege", "Role-based access control", "Regular access reviews"},
		},
		"CWE-287": {
			"Improper Authentication",
			[]string{"Multi-factor authentication", "Strong password policies", "Account lockout", "Session management"},
		},
		"CWE-352": {
			"Cross-Site Request Forgery (CSRF)",
			[]string{"CSRF tokens", "SameSite cookies", "Verify origin header", "Re-authentication for sensitive actions"},
		},
		"CWE-434": {
			"Unrestricted File Upload",
			[]string{"File type validation", "Content inspection", "Isolated storage", "Rename uploaded files"},
		},
		"CWE-502": {
			"Deserialization of Untrusted Data",
			[]string{"Avoid deserializing untrusted data", "Use safe serialization formats", "Input validation", "Integrity checks"},
		},
		"CWE-611": {
			"XXE (XML External Entity)",
			[]string{"Disable external entities", "Use less complex data formats", "Input validation", "Update XML parsers"},
		},
		"CWE-787": {
			"Out-of-bounds Write",
			[]string{"Bounds checking", "Safe memory functions", "ASLR/DEP", "Code review"},
		},
		"CWE-918": {
			"Server-Side Request Forgery (SSRF)",
			[]string{"URL validation", "Allowlist destinations", "Network segmentation", "Disable unnecessary protocols"},
		},
	}

	if data, ok := cweData[cwe]; ok {
		return data.name, data.mitigations
	}

	return "", nil
}

// --- Exploit Availability Tool ---

// ExploitCheckParams for check_exploit_availability tool
type ExploitCheckParams struct {
	CVEID string `json:"cve_id" jsonschema:"CVE ID to check for exploits (e.g., CVE-2024-1234)"`
}

// ExploitCheckResult for check_exploit_availability tool
type ExploitCheckResult struct {
	CVEID          string          `json:"cve_id"`
	HasExploits    bool            `json:"has_exploits"`
	GitHubPoCCount int             `json:"github_poc_count"`
	NucleiTemplate bool            `json:"has_nuclei_template"`
	GitHubPoCs     []GitHubPoCInfo `json:"github_pocs,omitempty"`
	NucleiURL      string          `json:"nuclei_url,omitempty"`
	ExploitDBURL   string          `json:"exploitdb_search_url"`
	RiskAssessment string          `json:"risk_assessment"`
}

// GitHubPoCInfo for exploit results
type GitHubPoCInfo struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	Stars       int    `json:"stars"`
}

func checkExploitAvailability(ctx tool.Context, params ExploitCheckParams) (ExploitCheckResult, error) {
	cveID, err := validateCVEID(params.CVEID)
	if err != nil {
		return ExploitCheckResult{}, err
	}

	// Fetch exploit info
	info, err := apiClient.FetchExploitInfo(cveID)
	if err != nil {
		return ExploitCheckResult{
			CVEID:        cveID,
			ExploitDBURL: fmt.Sprintf("https://www.exploit-db.com/search?cve=%s", cveID),
		}, nil
	}

	result := ExploitCheckResult{
		CVEID:          cveID,
		HasExploits:    info.HasExploits,
		GitHubPoCCount: info.GitHubPoCCount,
		NucleiTemplate: info.NucleiTemplate,
		NucleiURL:      info.NucleiURL,
		ExploitDBURL:   fmt.Sprintf("https://www.exploit-db.com/search?cve=%s", cveID),
	}

	// Convert PoC info
	for _, poc := range info.GitHubPoCs {
		result.GitHubPoCs = append(result.GitHubPoCs, GitHubPoCInfo{
			Name:        poc.Name,
			URL:         poc.URL,
			Description: poc.Description,
			Stars:       poc.Stars,
		})
	}

	// Risk assessment
	if info.HasExploits {
		if info.GitHubPoCCount >= 3 || info.NucleiTemplate {
			result.RiskAssessment = "HIGH - Multiple public exploits available, active exploitation likely"
		} else if info.GitHubPoCCount > 0 {
			result.RiskAssessment = "ELEVATED - Public PoC available, exploitation possible"
		} else {
			result.RiskAssessment = "MODERATE - Exploit references found"
		}
	} else {
		result.RiskAssessment = "STANDARD - No public exploits found (check Exploit-DB manually)"
	}

	return result, nil
}

// --- Patch Status Tool ---

// PatchCheckParams for check_patch_status tool
type PatchCheckParams struct {
	CVEID string `json:"cve_id" jsonschema:"CVE ID to check for patches (e.g., CVE-2024-1234)"`
}

// PatchCheckResult for check_patch_status tool
type PatchCheckResult struct {
	CVEID           string         `json:"cve_id"`
	HasPatch        bool           `json:"has_patch"`
	Advisories      []AdvisoryInfo `json:"advisories,omitempty"`
	PatchReferences []RefInfo      `json:"patch_references,omitempty"`
	AllReferences   []RefInfo      `json:"all_references,omitempty"`
	NVDURL          string         `json:"nvd_url"`
}

// AdvisoryInfo for patch results
type AdvisoryInfo struct {
	Vendor string `json:"vendor"`
	URL    string `json:"url"`
}

// RefInfo for reference info
type RefInfo struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

func checkPatchStatus(ctx tool.Context, params PatchCheckParams) (PatchCheckResult, error) {
	cveID, err := validateCVEID(params.CVEID)
	if err != nil {
		return PatchCheckResult{}, err
	}

	result := PatchCheckResult{
		CVEID:  cveID,
		NVDURL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
	}

	// Fetch patch info from NVD
	info, err := apiClient.FetchPatchInfo(cveID)
	if err != nil {
		return result, nil // Return with just NVD URL on error
	}

	result.HasPatch = info.HasPatch

	// Convert advisories
	for _, adv := range info.Advisories {
		result.Advisories = append(result.Advisories, AdvisoryInfo{
			Vendor: adv.Vendor,
			URL:    adv.URL,
		})
	}

	// Convert references, separating patch refs
	for _, ref := range info.References {
		refInfo := RefInfo{
			URL:    ref.URL,
			Source: ref.Source,
			Tags:   ref.Tags,
		}

		isPatch := false
		for _, tag := range ref.Tags {
			if strings.EqualFold(tag, "patch") || strings.EqualFold(tag, "vendor advisory") {
				isPatch = true
				break
			}
		}

		if isPatch {
			result.PatchReferences = append(result.PatchReferences, refInfo)
		}
		result.AllReferences = append(result.AllReferences, refInfo)
	}

	// Limit all references to avoid overwhelming output
	if len(result.AllReferences) > 10 {
		result.AllReferences = result.AllReferences[:10]
	}

	return result, nil
}

// --- Trend Analysis Tool ---

// TrendAnalysisParams for analyze_trends tool
type TrendAnalysisParams struct {
	Days   int    `json:"days,omitempty" jsonschema:"Number of days to analyze (default 90)"`
	Vendor string `json:"vendor,omitempty" jsonschema:"Filter by vendor"`
	CWE    string `json:"cwe,omitempty" jsonschema:"Filter by CWE"`
}

// TrendAnalysisResult for analyze_trends tool
type TrendAnalysisResult struct {
	Period          string          `json:"period"`
	TotalCVEs       int             `json:"total_cves_in_period"`
	NewCVEsPerWeek  []WeeklyCount   `json:"new_cves_per_week"`
	TopVendors      []VendorTrend   `json:"top_vendors"`
	TopCWEs         []CWETrend      `json:"top_cwes"`
	RansomwareTrend RansomwareTrend `json:"ransomware_trend"`
	RiskTrend       string          `json:"risk_trend"`
}

// WeeklyCount for trend data
type WeeklyCount struct {
	Week  string `json:"week"`
	Count int    `json:"count"`
}

// VendorTrend for vendor trends
type VendorTrend struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"`
	Change string `json:"change,omitempty"`
}

// CWETrend for CWE trends
type CWETrend struct {
	CWE   string `json:"cwe"`
	Name  string `json:"name,omitempty"`
	Count int    `json:"count"`
}

// RansomwareTrend for ransomware analysis
type RansomwareTrend struct {
	Total      int     `json:"total_in_period"`
	Percentage float64 `json:"percentage"`
}

func analyzeTrends(ctx tool.Context, params TrendAnalysisParams) (TrendAnalysisResult, error) {
	if err := ensureKEVData(); err != nil {
		return TrendAnalysisResult{}, fmt.Errorf("failed to fetch KEV data: %w", err)
	}

	days := params.Days
	if days <= 0 {
		days = 90
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	targetCWE := normalizeCWE(params.CWE)
	vendorFilter := strings.ToLower(params.Vendor)

	// Filter CVEs by date and criteria
	var filtered []struct {
		cve    string
		vendor string
		cwes   []string
		added  time.Time
		ransom bool
	}

	for _, v := range kevCache {
		if v.DateAdded.Before(cutoff) {
			continue
		}

		if vendorFilter != "" && !strings.Contains(strings.ToLower(v.VendorProject), vendorFilter) {
			continue
		}

		if targetCWE != "" {
			found := false
			for _, cwe := range v.CWEs {
				if normalizeCWE(cwe) == targetCWE {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		filtered = append(filtered, struct {
			cve    string
			vendor string
			cwes   []string
			added  time.Time
			ransom bool
		}{
			cve:    v.CVEID,
			vendor: v.VendorProject,
			cwes:   v.CWEs,
			added:  v.DateAdded,
			ransom: v.RansomwareUse,
		})
	}

	// Weekly breakdown
	weekCounts := make(map[string]int)
	for _, f := range filtered {
		year, week := f.added.ISOWeek()
		key := fmt.Sprintf("%d-W%02d", year, week)
		weekCounts[key]++
	}

	var weeklyData []WeeklyCount
	for week, count := range weekCounts {
		weeklyData = append(weeklyData, WeeklyCount{Week: week, Count: count})
	}
	sort.Slice(weeklyData, func(i, j int) bool {
		return weeklyData[i].Week < weeklyData[j].Week
	})

	// Vendor trends
	vendorCounts := make(map[string]int)
	for _, f := range filtered {
		vendorCounts[f.vendor]++
	}
	var vendorTrends []VendorTrend
	for v, c := range vendorCounts {
		vendorTrends = append(vendorTrends, VendorTrend{Vendor: v, Count: c})
	}
	sort.Slice(vendorTrends, func(i, j int) bool {
		return vendorTrends[i].Count > vendorTrends[j].Count
	})
	if len(vendorTrends) > 10 {
		vendorTrends = vendorTrends[:10]
	}

	// CWE trends
	cweCounts := make(map[string]int)
	for _, f := range filtered {
		for _, cwe := range f.cwes {
			cweCounts[cwe]++
		}
	}
	var cweTrends []CWETrend
	for cwe, c := range cweCounts {
		name, _ := getCWEInfo(cwe)
		cweTrends = append(cweTrends, CWETrend{CWE: cwe, Name: name, Count: c})
	}
	sort.Slice(cweTrends, func(i, j int) bool {
		return cweTrends[i].Count > cweTrends[j].Count
	})
	if len(cweTrends) > 10 {
		cweTrends = cweTrends[:10]
	}

	// Ransomware trend
	ransomCount := 0
	for _, f := range filtered {
		if f.ransom {
			ransomCount++
		}
	}
	ransomPct := 0.0
	if len(filtered) > 0 {
		ransomPct = float64(ransomCount) / float64(len(filtered)) * 100
	}

	// Risk trend assessment
	riskTrend := "STABLE"
	if len(weeklyData) >= 4 {
		// Compare recent vs earlier weeks
		recent := 0
		earlier := 0
		mid := len(weeklyData) / 2
		for i, w := range weeklyData {
			if i < mid {
				earlier += w.Count
			} else {
				recent += w.Count
			}
		}
		if recent > earlier*2 {
			riskTrend = "INCREASING - Recent activity significantly higher"
		} else if recent > earlier {
			riskTrend = "SLIGHTLY INCREASING"
		} else if earlier > recent*2 {
			riskTrend = "DECREASING - Recent activity lower"
		}
	}

	return TrendAnalysisResult{
		Period:         fmt.Sprintf("Last %d days", days),
		TotalCVEs:      len(filtered),
		NewCVEsPerWeek: weeklyData,
		TopVendors:     vendorTrends,
		TopCWEs:        cweTrends,
		RansomwareTrend: RansomwareTrend{
			Total:      ransomCount,
			Percentage: ransomPct,
		},
		RiskTrend: riskTrend,
	}, nil
}

// CreateAnalyticsTools creates all analytics tools for the agent
func CreateAnalyticsTools() ([]tool.Tool, error) {
	relatedTool, err := functiontool.New(
		functiontool.Config{
			Name:        "find_related_cves",
			Description: "Find CVEs related to a specific CVE, CWE, vendor, or product. Useful for discovering similar vulnerabilities or assessing scope of impact.",
		},
		findRelatedCVEs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create find_related_cves tool: %w", err)
	}

	vendorRiskTool, err := functiontool.New(
		functiontool.Config{
			Name:        "get_vendor_risk_profile",
			Description: "Get a comprehensive risk profile for a vendor including total CVEs, ransomware usage, EPSS scores, affected products, and overall risk score.",
		},
		getVendorRiskProfile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create get_vendor_risk_profile tool: %w", err)
	}

	batchTool, err := functiontool.New(
		functiontool.Config{
			Name:        "batch_analyze",
			Description: "Analyze multiple CVEs at once. Returns detailed analysis for each CVE plus aggregate statistics and risk prioritization.",
		},
		batchAnalyze,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create batch_analyze tool: %w", err)
	}

	cweTool, err := functiontool.New(
		functiontool.Config{
			Name:        "analyze_cwe",
			Description: "Deep dive analysis of a specific CWE (Common Weakness Enumeration). Shows all CVEs with this weakness, affected vendors/products, and suggested mitigations.",
		},
		analyzeCWE,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create analyze_cwe tool: %w", err)
	}

	exploitTool, err := functiontool.New(
		functiontool.Config{
			Name:        "check_exploit_availability",
			Description: "Check if public exploits exist for a CVE. Searches GitHub for PoCs, checks for Nuclei templates, and provides Exploit-DB search link.",
		},
		checkExploitAvailability,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create check_exploit_availability tool: %w", err)
	}

	patchTool, err := functiontool.New(
		functiontool.Config{
			Name:        "check_patch_status",
			Description: "Check if patches or vendor advisories are available for a CVE. Fetches references from NVD and identifies patch URLs.",
		},
		checkPatchStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create check_patch_status tool: %w", err)
	}

	trendTool, err := functiontool.New(
		functiontool.Config{
			Name:        "analyze_trends",
			Description: "Analyze vulnerability trends over time. Shows weekly CVE additions, top vendors/CWEs, ransomware trends, and risk trajectory.",
		},
		analyzeTrends,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create analyze_trends tool: %w", err)
	}

	return []tool.Tool{
		relatedTool,
		vendorRiskTool,
		batchTool,
		cweTool,
		exploitTool,
		patchTool,
		trendTool,
	}, nil
}
