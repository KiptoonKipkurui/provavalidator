package check

import (
	"github.com/kiptoonkipkurui/provavalidator/pkg/drift"
	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
)

type Result struct {
	Image string `json:"image"`
	// Provenence
	Provenence struct {
		Required bool   `json:"required"`
		Passed   bool   `json:"passed"`
		Message  string `json:"message,omitempty"`
	} `json:"provenence"`
	// SBOM (useful context)
	SBOM struct {
		Packages *sbom.ResolvedSBOM `json:"packages,omitempty"`
	} `json:"sbom"`

	// Vulnerabilities
	Vuln struct {
		FailOn     string         `json:"fail_on,omitempty"`
		Summary    vuln.Summary   `json:"summary"`
		Findings   []vuln.Finding `json:"findings,omitempty"`
		Violations []vuln.Finding `json:"violations,omitempty"`
	} `json:"vulnerabilities"`

	// Drift
	Drift struct {
		Baseline   string             `json:"baseline,omitempty"`
		Result     *drift.DriftResult `json:"result,omitempty"`
		PolicyFail bool               `json:"policyFail"`
		Message    string             `json:"message,omitempty"`
	} `json:"drift"`

	Passed bool `json:"passed"`
}
