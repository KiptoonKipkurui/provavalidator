package sbom

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
	syftsobm "github.com/anchore/syft/syft/sbom"
)

// Software Package Data Exchange (SPDX) is an open standard (or format) for communicating Software Bill of Materials (SBOM) information including components, licenses, copyrights, and security references.
// NormalizePackage converts Syft's SBOM model to stable NormalizedPackage entries
//
// Why normalize?
// - SPDX vs CycloneDX vs Syft-JSON vary in how they represent ecosystems, licenses, locations.
// - you want *one* policy/vuln pipeline regardless of input format.
//
// Notes:
// - pkg.Package includes: Name, Version, FoundBy, Locations (LocationSet), Licenses (LicenseSet), Type, PURL. :contentReference[oaicite:1]{index=1}
func NormalizePackage(doc *syftsobm.SBOM) []NormalizedPackage {
	if doc == nil {
		return nil
	}

	// Sorted() gives deterministic output , which is great for tests and CI diffs
	pkgs := doc.Artifacts.Packages.Sorted()

	out := make([]NormalizedPackage, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, normalizeOne(p))
	}

	return out
}

func normalizeOne(p pkg.Package) NormalizedPackage {
	licenses := normalizeLicenses(p.Licenses)
	locations := normalizeLocations(p.Locations)

	return NormalizedPackage{
		Name:      p.Name,
		Version:   p.Version,
		Type:      p.Type.String(),
		Licences:  licenses,
		Locations: locations,
		PURL:      strings.TrimSpace(p.PURL),
		FoundBy:   p.FoundBy,
	}
}

func normalizeLicenses(ls pkg.LicenseSet) []string {
	// LicenseSet can be empty; ToSlice sorts with optional sorters
	// We keep this conservative: prefer SPDExpression if available else raw value
	l := ls.ToSlice(func(a, b pkg.License) int {
		// basic stable ordering
		if a.SPDXExpression != b.SPDXExpression {
			if a.SPDXExpression < b.SPDXExpression {
				return -1
			}
			return 1
		}

		if a.Value < b.Value {
			return -1
		}

		if a.Value > b.Value {
			return 1
		}

		return 0
	})

	out := make([]string, 0, len(l))
	seen := map[string]struct{}{}
	for _, lic := range l {
		s := strings.TrimSpace(lic.SPDXExpression)
		if s == "" {
			s = strings.TrimSpace(lic.Value)
		}
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}
