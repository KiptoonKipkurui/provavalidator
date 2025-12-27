package sbom

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
)

func TestNormalizePackages_Basic(t *testing.T) {
	// Build a tiny Syft SBOM model in-memory (no registries, no decoding).
	p1 := pkg.Package{
		Name:    "openssl",
		Version: "3.0.2",
		Type:    pkg.DebPkg,
		PURL:    "pkg:deb/debian/openssl@3.0.2",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromType("Apache-2.0", license.Declared), // value is enough for our purposes
		),
		Locations: file.NewLocationSet(
			file.NewLocation("/usr/lib/x86_64-linux-gnu/libssl.so.3"),
		),
		FoundBy: "dpkg-cataloger",
	}

	doc := &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: pkg.NewCollection(p1),
		},
	}

	n := NormalizePackage(doc)
	if len(n) != 1 {
		t.Fatalf("expected 1 package, got %d", len(n))
	}

	if n[0].Name != "openssl" {
		t.Fatalf("expected openssl, got %q", n[0].Name)
	}
	if n[0].Type == "" || n[0].PURL == "" {
		t.Fatalf("expected type+purl to be set, got type=%q purl=%q", n[0].Type, n[0].PURL)
	}
	if len(n[0].Locations) == 0 {
		t.Fatalf("expected at least one location")
	}
}
