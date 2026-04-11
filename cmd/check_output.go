package cmd

import (
	"fmt"

	"github.com/kiptoonkipkurui/provavalidator/pkg/check"
	"github.com/kiptoonkipkurui/provavalidator/pkg/drift"
	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
)

func printCombinedText(r *check.Result) {
	fmt.Printf("Image: %s\n\n", r.Image)

	// Provenance
	if r.Provenence.Required {
		if r.Provenence.Passed {
			fmt.Println("Provenance: ✅ satisfied")
		} else {
			fmt.Printf("Provenance: ❌ %s\n", r.Provenence.Message)
		}
	} else {
		fmt.Println("Provenance: (not required)")
	}

	// SBOM
	if r.SBOM.Packages != nil && len(r.SBOM.Packages.Packages) > 0 {
		fmt.Printf("SBOM: %d packages (source: %s)\n\n", len(r.SBOM.Packages.Packages), r.SBOM.Packages.Source)
	}

	// Vulnerabilities
	fmt.Println("Vulnerabilities:")
	printVulnSummary(r.Vuln.Summary)
	if len(r.Vuln.Violations) > 0 {
		fmt.Printf("\n❌ Vulnerability policy violation (fail-on: %s)\n\n", r.Vuln.FailOn)
		for _, f := range r.Vuln.Violations {
			fmt.Println(vuln.FormatFinding(f))
		}
	}
	fmt.Println()

	// Drift
	if r.Drift.Result != nil {
		fmt.Println("Drift:")
		fmt.Println(drift.FormatDrift(r.Drift.Result))
		if r.Drift.PolicyFail {
			fmt.Printf("\n❌ Drift policy violation: %s\n", r.Drift.Message)
		}
	}
}

func printVulnSummary(s vuln.Summary) {
	fmt.Printf("  Critical: %d\n", s.Critical)
	fmt.Printf("  High:     %d\n", s.High)
	fmt.Printf("  Medium:   %d\n", s.Medium)
	fmt.Printf("  Low:      %d\n", s.Low)
	fmt.Printf("  Total:    %d\n", s.Total)
}
