package vuln

import (
	"context"
	"fmt"
	"strings"

	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
)

type Summary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

func Summarize(findings []Finding) Summary {
	var s Summary
	s.Total = len(findings)

	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		default:
			s.Unknown++
		}
	}
	return s
}

func ScanVulnerabilities(ctx context.Context, image string) ([]Finding, error) {
	// TODO: integrate Grype or OSV queries
	fmt.Println("[vuln] Scanning vulnerabilities for:", image)

	resSbom, err := sbom.ExtractSBOM(ctx, image)

	if err != nil {
		return nil, fmt.Errorf("failed to extract SBOM: %w", err)
	}

	client := NewOSVClient()
	findings, err := ScanNormalizedPackagesWithOSV(ctx, client, resSbom.Packages, ScanOptions{
		RequireVersion: true,
		RequirePURL:    true,
	})
	return findings, err
}

type Policy struct {
	FailOn Severity
}

func EnforcePolicy(findings []Finding, p Policy) error {
	for _, f := range findings {
		if severityRank(f.Severity) >= severityRank(p.FailOn) {
			return fmt.Errorf(
				"policy violation: %s vulnerability %s in %s@%s",
				f.Severity,
				f.VulnID,
				f.PackageName,
				f.PackageVersion,
			)
		}
	}
	return nil
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
func FormatFinding(f Finding) string {
	return fmt.Sprintf(
		"- [%s] %s (%s)\n  Package: %s@%s\n  %s\n",
		f.Severity,
		f.VulnID,
		f.Summary,
		f.PackageName,
		f.PackageVersion,
		f.Details,
	)
}
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	default:
		return "", fmt.Errorf("invalid severity %q", s)
	}
}

func FilterBySeverity(findings []Finding, min Severity) []Finding {
	out := []Finding{}
	for _, f := range findings {
		if severityRank(f.Severity) >= severityRank(min) {
			out = append(out, f)
		}
	}
	return out
}
