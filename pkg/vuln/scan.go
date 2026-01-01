package vuln

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
)

// ScanOptions control matching behaviour
type ScanOptions struct {
	// If true, packages without version are skipped (OSV version queries need a version).
	RequireVersion bool

	// If true, skip packages that lack PURL and cant be mapped
	RequirePURL bool
}

func ScanNormalizedPackagesWithOSV(ctx context.Context, client *OSVClient, pkgs []sbom.NormalizedPackage, opts ScanOptions) ([]Finding, error) {
	if client == nil {
		client = NewOSVClient()
	}

	queries := make([]osvQuery, 0, len(pkgs))
	index := make([]sbom.NormalizedPackage, 0, len(pkgs)) // track which query maps to which package

	for _, p := range pkgs {
		q, ok, reason := toOSVQuery(p, opts)

		if !ok {
			// not an error; just not queryable under current policy
			_ = reason
			continue
		}

		queries = append(queries, q)
		index = append(index, p)
	}
	results, err := client.QueryBatch(ctx, queries)

	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)

	for i, r := range results {
		p := index[i]
		for _, v := range r.Vulns {
			score, sev := bestEffortSeverity(v.Severity)

			findings = append(findings, Finding{
				PackageName:    p.Name,
				PackageVersion: p.Version,
				PURL:           p.PURL,
				VulnID:         v.ID,
				Summary:        v.Summary,
				Details:        v.Details,
				Aliases:        v.Aliases,
				CVSSScore:      score,
				Severity:       sev,
			})
		}
	}

	return findings, nil
}

// OSV query rules: use either top-level version or versioned PURL not both. :contentReference[oaicite:2]{index=2}
func toOSVQuery(p sbom.NormalizedPackage, opts ScanOptions) (osvQuery, bool, string) {
	if opts.RequireVersion && strings.TrimSpace(p.Version) == "" && !purlHasVersion(p.PURL) {
		return osvQuery{}, false, "missing version"
	}

	purl := strings.TrimSpace(p.PURL)
	if purl == "" && opts.RequirePURL {
		return osvQuery{}, false, "missing purl"
	}

	// Best practice: prefer PURL queries when available (ecosystem mapping is painful for OS pkgs).
	if purl != "" {
		if purlHasVersion(purl) {
			return osvQuery{
				Package: &osvPackage{
					PURL: purl,
				},
			}, true, ""
		}

		ver := strings.TrimSpace(p.Version)
		if ver == "" && opts.RequireVersion {
			return osvQuery{}, false, "missing version for unversioned purl"
		}

		q := osvQuery{Package: &osvPackage{PURL: purl}}
		if ver != "" {
			q.Version = ver
		}
		return q, true, ""
	}

	// Fallsback: name+ecosystem
	// Fallback: name+ecosystem (only if you implement mapping elsewhere).
	// Keep this disabled by default; you can add ecosystem mapping later.
	return osvQuery{}, false, "no purl; ecosystem mapping not enabled"
}

func purlHasVersion(purl string) bool {
	// Minimal check: PURLs put version after '@'
	// e.g. pkg:pypi/jinja2@3.1.4
	i := strings.IndexByte(purl, '@')
	return i > 0 && i < len(purl)-1
}

func bestEffortSeverity(entries []osvSeverityEntry) (score float64, sev Severity) {
	// Prefer numeric "score" if present; else unknown.
	best := -1.0
	for _, e := range entries {
		s := strings.TrimSpace(e.Score)
		if s == "" {
			continue
		}
		// Some OSV responses use numeric strings; some may be vectors.
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			if f > best {
				best = f
			}
		}
	}
	if best < 0 {
		return 0, SeverityUnknown
	}
	return best, cvssToSeverity(best)
}

func cvssToSeverity(score float64) Severity {
	// Common CVSS buckets:
	// 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

func (s Severity) String() string { return fmt.Sprintf("%s", string(s)) }
