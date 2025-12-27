package sbom

// NormalizePackage is stable, 'policy-friendly' view of a package
// Keep this small and consistent; it becomes contract for policy + vulns scan
type NormalizedPackage struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type,omitempty"` // ecosystem (npm, apk, deb, rpm, go-module, ...)
	PURL      string   `json:"purl,omitempty"`
	Licences  []string `json:"licences,omitempty"`
	Locations []string `json:"locations,omitempty"`
	FoundBy   string   `json:"found_by,omitempty"` // cataloger name if present
}
