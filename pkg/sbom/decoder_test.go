package sbom

import (
	"os"
	"testing"
)

func TestDecode_CycloneDX(t *testing.T) {
	b, err := os.ReadFile("testdata/cyclonedx.json")
	if err != nil {
		t.Fatal(err)
	}

	res, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if res.SBOM == nil {
		t.Fatal("expected SBOM, got nil")
	}

	if res.FormatID == "" {
		t.Fatal("expected format to be detected")
	}
}

// TODO: add spdx.json
func TestDecode_SPDX(t *testing.T) {
	b, err := os.ReadFile("testdata/spdx.json")
	if err != nil {
		t.Fatal(err)
	}

	res, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if res.SBOM == nil {
		t.Fatal("expected SBOM, got nil")
	}
}
