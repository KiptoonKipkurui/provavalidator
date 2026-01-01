// OSV query batch minimal fields.
// Docs: POST /v1/querybatch; each query item follows /v1/query rules.  :contentReference[oaicite:1]{index=1}
package vuln

type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}
type osvQuery struct {
	Package *osvPackage `json:"package"`
	Version string      `json:"version,omitempty"`
	Commit  string      `json:"commit,omitempty"`
}

type osvPackage struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID       string             `json:"id"`
	Summary  string             `json:"summary,omitempty"`
	Details  string             `json:"details,omitempty"`
	Aliases  []string           `json:"aliases,omitempty"`
	Severity []osvSeverityEntry `json:"severity,omitempty"`
}

type osvSeverityEntry struct {
	Type  string `json:"type"`  // e.g., "CVSS_V3"
	Score string `json:"score"` // e.g., "7.5" or "CVSS:3.1/AV:N/..."
}
