package vuln

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	PackageName    string   `json:"packageName"`
	PackageVersion string   `json:"packageVersion,omitempty"`
	PackageType    string   `json:"packageType,omitempty"`
	PURL           string   `json:"purl,omitempty"`
	VulnID         string   `json:"vulnId"`
	Summary        string   `json:"summary,omitempty"`
	Details        string   `json:"details,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`

	// Best effort: OSV severity can be CVSSv2/v3/v4 etc; we normalize to a single float.
	CVSSScore float64  `json:"cvssScore,omitempty"`
	Severity  Severity `json:"severity,omitempty"`
}
