package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Test helpers (shared with exploits_test.go via same package) ---

// rewriteTransport is a custom http.RoundTripper that redirects all requests
// to a test server, preserving the original path and query string.
type rewriteTransport struct {
	targetURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	// Extract host from targetURL (strip scheme)
	host := strings.TrimPrefix(t.targetURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	req.URL.Host = host
	return http.DefaultTransport.RoundTrip(req)
}

// setupTestServer creates a test server and a Client wired to route all
// requests through it. The server is cleaned up when the test ends.
func setupTestServer(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	client := NewClientWithHTTPClient(&http.Client{
		Transport: &rewriteTransport{targetURL: ts.URL},
		Timeout:   5 * time.Second,
	})
	return client
}

// resetAllCaches clears all global caches so tests are independent.
func resetAllCaches() {
	cvssCacheMu.Lock()
	cvssCacheEntries = make(map[string]cvssCacheEntry)
	cvssCacheMu.Unlock()

	exploitCacheMu.Lock()
	exploitCacheEntries = make(map[string]exploitCacheEntry)
	exploitCacheMu.Unlock()

	patchCacheMu.Lock()
	patchCacheEntries = make(map[string]patchCacheEntry)
	patchCacheMu.Unlock()
}

// --- Fixture builders ---

func makeKEVResponse(vulns []VulnerabilityJSON) KEVResponse {
	return KEVResponse{
		Title:           "CISA KEV Catalog",
		CatalogVersion:  "2024.01.01",
		DateReleased:    "2024-01-01",
		Count:           len(vulns),
		Vulnerabilities: vulns,
	}
}

func makeEPSSResponse(data []EPSSData) EPSSResponse {
	return EPSSResponse{
		Status:     "OK",
		StatusCode: 200,
		Version:    "1.0",
		Total:      len(data),
		Data:       data,
	}
}

func makeNVDResponse(metrics NVDMetrics) NVDResponse {
	return NVDResponse{
		ResultsPerPage: 1,
		TotalResults:   1,
		Vulnerabilities: []NVDVulnWrapper{
			{CVE: NVDCVEItem{ID: "CVE-2024-1234", Metrics: metrics}},
		},
	}
}

// --- Tests ---

func TestNewClient(t *testing.T) {
	c := NewClient()
	if c == nil {
		t.Fatal("NewClient() returned nil")
	}
	if c.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if c.httpClient.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", c.httpClient.Timeout)
	}
}

func TestFetchVulnerabilities(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantCount  int
		wantErr    bool
		checkFirst func(t *testing.T, vulns []VulnerabilityJSON)
	}{
		{
			name: "success with field mapping and date parsing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := makeKEVResponse([]VulnerabilityJSON{
					{
						CVEID:                      "CVE-2024-1234",
						VendorProject:              "TestVendor",
						Product:                    "TestProduct",
						VulnerabilityName:          "Test Vuln",
						DateAdded:                  "2024-01-15",
						ShortDescription:           "A test vulnerability",
						RequiredAction:             "Patch it",
						DueDate:                    "2024-02-15",
						KnownRansomwareCampaignUse: "Known",
						Notes:                      "Some notes",
						CWEs:                       []string{"CWE-79"},
					},
					{
						CVEID:                      "CVE-2024-5678",
						VendorProject:              "OtherVendor",
						Product:                    "OtherProduct",
						VulnerabilityName:          "Other Vuln",
						DateAdded:                  "2024-03-01",
						ShortDescription:           "Another test vulnerability",
						RequiredAction:             "Update it",
						DueDate:                    "2024-04-01",
						KnownRansomwareCampaignUse: "Unknown",
						Notes:                      "",
					},
				})
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			wantCount: 2,
		},
		{
			name: "empty vulnerability list",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := makeKEVResponse(nil)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			wantCount: 0,
		},
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{invalid json`)
			},
			wantErr: true,
		},
		{
			name: "non-200 status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupTestServer(t, tt.handler)

			vulns, err := client.FetchVulnerabilities()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(vulns) != tt.wantCount {
				t.Fatalf("got %d vulns, want %d", len(vulns), tt.wantCount)
			}

			if tt.wantCount >= 1 {
				v := vulns[0]
				if v.CVEID != "CVE-2024-1234" {
					t.Errorf("CVEID = %q, want CVE-2024-1234", v.CVEID)
				}
				if v.VendorProject != "TestVendor" {
					t.Errorf("VendorProject = %q, want TestVendor", v.VendorProject)
				}
				if v.Product != "TestProduct" {
					t.Errorf("Product = %q, want TestProduct", v.Product)
				}
				if v.DateAdded.Format("2006-01-02") != "2024-01-15" {
					t.Errorf("DateAdded = %v, want 2024-01-15", v.DateAdded)
				}
				if v.DueDate.Format("2006-01-02") != "2024-02-15" {
					t.Errorf("DueDate = %v, want 2024-02-15", v.DueDate)
				}
				if !v.RansomwareUse {
					t.Error("RansomwareUse = false, want true for 'Known'")
				}
			}
			if tt.wantCount >= 2 {
				v := vulns[1]
				if v.RansomwareUse {
					t.Error("RansomwareUse = true, want false for 'Unknown'")
				}
			}
		})
	}
}

func TestFetchVulnerabilities_NetworkError(t *testing.T) {
	// Create a client pointing at a closed server to simulate network error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close() // Immediately close to cause connection refused

	client := NewClientWithHTTPClient(&http.Client{
		Transport: &rewriteTransport{targetURL: ts.URL},
		Timeout:   1 * time.Second,
	})

	_, err := client.FetchVulnerabilities()
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestFetchEPSSScores(t *testing.T) {
	tests := []struct {
		name      string
		cveIDs    []string
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		{
			name:   "success with scores",
			cveIDs: []string{"CVE-2024-1234", "CVE-2024-5678"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := makeEPSSResponse([]EPSSData{
					{CVE: "CVE-2024-1234", EPSS: "0.95", Percentile: "0.99"},
					{CVE: "CVE-2024-5678", EPSS: "0.01", Percentile: "0.10"},
				})
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			wantCount: 2,
		},
		{
			name:   "empty input",
			cveIDs: nil,
			handler: func(w http.ResponseWriter, r *http.Request) {
				t.Error("should not make request for empty input")
			},
			wantCount: 0,
		},
		{
			name:   "server error returns empty gracefully",
			cveIDs: []string{"CVE-2024-1234"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantCount: 0,
		},
		{
			name:   "malformed scores parsed as zero",
			cveIDs: []string{"CVE-2024-1234"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := makeEPSSResponse([]EPSSData{
					{CVE: "CVE-2024-1234", EPSS: "not_a_number", Percentile: "also_bad"},
				})
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			wantCount: 1, // Entry exists but with zero values
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupTestServer(t, tt.handler)

			scores, err := client.FetchEPSSScores(tt.cveIDs)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(scores) != tt.wantCount {
				t.Fatalf("got %d scores, want %d", len(scores), tt.wantCount)
			}
		})
	}
}

func TestFetchEPSSScores_Chunking(t *testing.T) {
	var requestCount atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		cveParam := r.URL.Query().Get("cve")
		ids := strings.Split(cveParam, ",")

		var data []EPSSData
		for _, id := range ids {
			data = append(data, EPSSData{CVE: id, EPSS: "0.5", Percentile: "0.5"})
		}
		resp := makeEPSSResponse(data)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	client := setupTestServer(t, handler)

	// Generate 250 CVE IDs — should result in 3 chunks (100+100+50)
	cveIDs := make([]string, 250)
	for i := range cveIDs {
		cveIDs[i] = fmt.Sprintf("CVE-2024-%04d", i)
	}

	scores, err := client.FetchEPSSScores(cveIDs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scores) != 250 {
		t.Errorf("got %d scores, want 250", len(scores))
	}
	if got := requestCount.Load(); got != 3 {
		t.Errorf("made %d requests, want 3 (chunks of 100)", got)
	}
}

func TestFetchEPSSScores_PartialFailure(t *testing.T) {
	var requestCount atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count == 2 {
			// Fail the second chunk
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		cveParam := r.URL.Query().Get("cve")
		ids := strings.Split(cveParam, ",")
		var data []EPSSData
		for _, id := range ids {
			data = append(data, EPSSData{CVE: id, EPSS: "0.5", Percentile: "0.5"})
		}
		resp := makeEPSSResponse(data)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	client := setupTestServer(t, handler)

	// 200 IDs = 2 chunks; second chunk fails
	cveIDs := make([]string, 200)
	for i := range cveIDs {
		cveIDs[i] = fmt.Sprintf("CVE-2024-%04d", i)
	}

	scores, err := client.FetchEPSSScores(cveIDs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still have results from the first chunk
	if len(scores) != 100 {
		t.Errorf("got %d scores, want 100 (first chunk only)", len(scores))
	}
}

func TestFetchCVSS(t *testing.T) {
	tests := []struct {
		name        string
		cveID       string
		metrics     NVDMetrics
		wantVersion string
		wantScore   float64
		wantErr     bool
		errContains string
	}{
		{
			name:  "prefers v3.1 over v3.0 and v2.0",
			cveID: "CVE-2024-1234",
			metrics: NVDMetrics{
				CVSSMetricV31: []CVSSMetricV31{{
					Source:   "nvd@nist.gov",
					Type:     "Primary",
					CVSSData: CVSSData{Version: "3.1", BaseScore: 9.8, BaseSeverity: "CRITICAL", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				}},
				CVSSMetricV30: []CVSSMetricV30{{
					Source:   "cna@vendor.com",
					Type:     "Secondary",
					CVSSData: CVSSData{Version: "3.0", BaseScore: 7.5, BaseSeverity: "HIGH", VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
				}},
			},
			wantVersion: "3.1",
			wantScore:   9.8,
		},
		{
			name:  "falls back to v3.0 when no v3.1",
			cveID: "CVE-2024-1234",
			metrics: NVDMetrics{
				CVSSMetricV30: []CVSSMetricV30{{
					Source:   "nvd@nist.gov",
					Type:     "Primary",
					CVSSData: CVSSData{Version: "3.0", BaseScore: 7.5, BaseSeverity: "HIGH", VectorString: "CVSS:3.0/AV:N"},
				}},
			},
			wantVersion: "3.0",
			wantScore:   7.5,
		},
		{
			name:  "falls back to v2.0 when no v3.x",
			cveID: "CVE-2024-1234",
			metrics: NVDMetrics{
				CVSSMetricV2: []CVSSMetricV2{{
					Source:       "nvd@nist.gov",
					Type:         "Primary",
					CVSSData:     CVSSDataV2{Version: "2.0", BaseScore: 5.0, VectorString: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
					BaseSeverity: "MEDIUM",
				}},
			},
			wantVersion: "2.0",
			wantScore:   5.0,
		},
		{
			name:        "no metrics returns error",
			cveID:       "CVE-2024-1234",
			metrics:     NVDMetrics{},
			wantErr:     true,
			errContains: "no CVSS data",
		},
		{
			name:        "input normalization (lowercase + whitespace)",
			cveID:       "  cve-2024-1234  ",
			metrics:     NVDMetrics{CVSSMetricV31: []CVSSMetricV31{{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSData{Version: "3.1", BaseScore: 9.8, BaseSeverity: "CRITICAL"}}}},
			wantVersion: "3.1",
			wantScore:   9.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := makeNVDResponse(tt.metrics)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			})
			client := setupTestServer(t, handler)

			score, err := client.FetchCVSS(tt.cveID)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if score.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", score.Version, tt.wantVersion)
			}
			if score.Score != tt.wantScore {
				t.Errorf("Score = %v, want %v", score.Score, tt.wantScore)
			}
		})
	}
}

func TestFetchCVSS_NoCVEFound(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{ResultsPerPage: 0, TotalResults: 0}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	client := setupTestServer(t, handler)

	_, err := client.FetchCVSS("CVE-2099-99999")
	if err == nil {
		t.Fatal("expected error for missing CVE")
	}
	if !strings.Contains(err.Error(), "no CVE data") {
		t.Errorf("error %q does not mention missing CVE", err.Error())
	}
}

func TestFetchCVSSAll(t *testing.T) {
	t.Run("primary and secondary separation", func(t *testing.T) {
		resetAllCaches()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics := NVDMetrics{
				CVSSMetricV31: []CVSSMetricV31{
					{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSData{Version: "3.1", BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
					{Source: "cna@vendor.com", Type: "Secondary", CVSSData: CVSSData{Version: "3.1", BaseScore: 8.1, BaseSeverity: "HIGH"}},
				},
			}
			resp := makeNVDResponse(metrics)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		client := setupTestServer(t, handler)

		data, err := client.FetchCVSSAll("CVE-2024-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data.Primary == nil {
			t.Fatal("Primary is nil")
		}
		if data.Primary.Score != 9.8 {
			t.Errorf("Primary.Score = %v, want 9.8", data.Primary.Score)
		}
		if data.Primary.Source != "nvd@nist.gov" {
			t.Errorf("Primary.Source = %q, want nvd@nist.gov", data.Primary.Source)
		}
		if len(data.Secondary) != 1 {
			t.Fatalf("got %d secondary scores, want 1", len(data.Secondary))
		}
		if data.Secondary[0].Score != 8.1 {
			t.Errorf("Secondary[0].Score = %v, want 8.1", data.Secondary[0].Score)
		}
	})

	t.Run("v3.0 fallback when no v3.1", func(t *testing.T) {
		resetAllCaches()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics := NVDMetrics{
				CVSSMetricV30: []CVSSMetricV30{
					{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSData{Version: "3.0", BaseScore: 7.5, BaseSeverity: "HIGH"}},
				},
			}
			resp := makeNVDResponse(metrics)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		client := setupTestServer(t, handler)

		data, err := client.FetchCVSSAll("CVE-2024-9999")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data.Primary == nil {
			t.Fatal("Primary is nil after v3.0 fallback")
		}
		if data.Primary.Version != "3.0" {
			t.Errorf("Primary.Version = %q, want 3.0", data.Primary.Version)
		}
	})

	t.Run("v2.0 fallback when no v3.x", func(t *testing.T) {
		resetAllCaches()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics := NVDMetrics{
				CVSSMetricV2: []CVSSMetricV2{
					{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSDataV2{Version: "2.0", BaseScore: 5.0}, BaseSeverity: "MEDIUM"},
				},
			}
			resp := makeNVDResponse(metrics)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		client := setupTestServer(t, handler)

		data, err := client.FetchCVSSAll("CVE-2024-8888")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data.Primary == nil {
			t.Fatal("Primary is nil after v2.0 fallback")
		}
		if data.Primary.Version != "2.0" {
			t.Errorf("Primary.Version = %q, want 2.0", data.Primary.Version)
		}
	})

	t.Run("cache hit avoids HTTP request", func(t *testing.T) {
		resetAllCaches()
		var requestCount atomic.Int32

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)
			metrics := NVDMetrics{
				CVSSMetricV31: []CVSSMetricV31{
					{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSData{Version: "3.1", BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
				},
			}
			resp := makeNVDResponse(metrics)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		client := setupTestServer(t, handler)

		// First call — hits server
		_, err := client.FetchCVSSAll("CVE-2024-7777")
		if err != nil {
			t.Fatalf("first call: %v", err)
		}
		// Second call — should use cache
		_, err = client.FetchCVSSAll("CVE-2024-7777")
		if err != nil {
			t.Fatalf("second call: %v", err)
		}

		if got := requestCount.Load(); got != 1 {
			t.Errorf("made %d requests, want 1 (second should be cached)", got)
		}
	})

	t.Run("cache expiry causes re-fetch", func(t *testing.T) {
		resetAllCaches()

		var requestCount atomic.Int32
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)
			metrics := NVDMetrics{
				CVSSMetricV31: []CVSSMetricV31{
					{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSData{Version: "3.1", BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
				},
			}
			resp := makeNVDResponse(metrics)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		client := setupTestServer(t, handler)

		// First call
		_, err := client.FetchCVSSAll("CVE-2024-6666")
		if err != nil {
			t.Fatalf("first call: %v", err)
		}

		// Manually expire the cache entry
		cvssCacheMu.Lock()
		if entry, ok := cvssCacheEntries["CVE-2024-6666"]; ok {
			entry.fetchedAt = time.Now().Add(-2 * cvssCacheTTL)
			cvssCacheEntries["CVE-2024-6666"] = entry
		}
		cvssCacheMu.Unlock()

		// Second call — cache expired, should hit server again
		_, err = client.FetchCVSSAll("CVE-2024-6666")
		if err != nil {
			t.Fatalf("second call: %v", err)
		}

		if got := requestCount.Load(); got != 2 {
			t.Errorf("made %d requests, want 2 (cache should have expired)", got)
		}
	})

	t.Run("input normalization", func(t *testing.T) {
		resetAllCaches()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify normalized CVE ID in query
			cveParam := r.URL.Query().Get("cveId")
			if cveParam != "CVE-2024-1234" {
				t.Errorf("query param cveId = %q, want CVE-2024-1234", cveParam)
			}
			metrics := NVDMetrics{
				CVSSMetricV31: []CVSSMetricV31{
					{Source: "nvd@nist.gov", Type: "Primary", CVSSData: CVSSData{Version: "3.1", BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
				},
			}
			resp := makeNVDResponse(metrics)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		client := setupTestServer(t, handler)

		_, err := client.FetchCVSSAll("  cve-2024-1234  ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRateLimitedGet(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	client := setupTestServer(t, handler)

	start := time.Now()
	for i := 0; i < 3; i++ {
		resp, err := client.rateLimitedGet("http://localhost/test")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)

	// 3 requests with 100ms interval between them = at least 200ms total
	if elapsed < 200*time.Millisecond {
		t.Errorf("3 requests took %v, want >= 200ms (rate limiting)", elapsed)
	}
}
