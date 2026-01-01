package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
)

func TestScanNormalizedPackagesWithOSV_QueryBatchAndFindings(t *testing.T) {
	// Fake OSV server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req osvQueryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Ensure we did NOT violate version rules:
		// if purl is versioned, version field should be empty.
		for _, q := range req.Queries {
			if q.Package != nil && q.Package.PURL != "" && purlHasVersion(q.Package.PURL) && q.Version != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"version rule violated"}`))
				return
			}
		}

		// Respond with one vuln for each query
		resp := osvQueryBatchResponse{Results: make([]osvQueryResult, len(req.Queries))}
		for i := range req.Queries {
			resp.Results[i] = osvQueryResult{
				Vulns: []osvVulnerability{
					{
						ID:      "OSV-2025-TEST",
						Summary: "test vuln",
						Severity: []osvSeverityEntry{
							{Type: "CVSS_V3", Score: "9.8"},
						},
					},
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewOSVClient()
	client.BaseURl = srv.URL
	client.MaxQueriesPerBatch = 50

	pkgs := []sbom.NormalizedPackage{
		// Unversioned PURL + version field => OK
		{Name: "jinja2", Version: "3.1.4", Type: "python", PURL: "pkg:pypi/jinja2"},
		// Versioned PURL => must omit version field
		{Name: "requests", Version: "2.32.0", Type: "python", PURL: "pkg:pypi/requests@2.32.0"},
	}

	findings, err := ScanNormalizedPackagesWithOSV(context.Background(), client, pkgs, ScanOptions{
		RequireVersion: true,
		RequirePURL:    true,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
}
