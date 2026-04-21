package sbom

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/kiptoonkipkurui/provavalidator/pkg/attestation"
)

func TestExtractSBOM_PrefersVerifiedAttestation(t *testing.T) {
	originalExtract := extractAttestedSBOM
	originalGenerate := generateImageSBOM
	t.Cleanup(func() {
		extractAttestedSBOM = originalExtract
		generateImageSBOM = originalGenerate
	})

	payload, err := os.ReadFile("testdata/spdx.json")
	if err != nil {
		t.Fatal(err)
	}

	extractAttestedSBOM = func(context.Context, string) ([]byte, string, error) {
		return payload, "https://spdx.dev/Document", nil
	}
	generateImageSBOM = func(context.Context, string) (*ResolvedSBOM, error) {
		t.Fatal("expected signed attestation to avoid Syft fallback")
		return nil, nil
	}

	resolved, err := ExtractSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if err != nil {
		t.Fatalf("ExtractSBOM returned error: %v", err)
	}

	if resolved.Source != SourceAttestation {
		t.Fatalf("unexpected source: got %q want %q", resolved.Source, SourceAttestation)
	}
	if resolved.Format != "spdx-json" {
		t.Fatalf("unexpected format: got %q want %q", resolved.Format, "spdx-json")
	}
	if len(resolved.Packages) == 0 {
		t.Fatal("expected normalized packages from attested SBOM")
	}
	if len(resolved.RawPayload) == 0 {
		t.Fatal("expected attested SBOM payload to be preserved")
	}
}

func TestExtractSBOM_FallsBackWhenSignedSBOMMissing(t *testing.T) {
	originalExtract := extractAttestedSBOM
	originalGenerate := generateImageSBOM
	t.Cleanup(func() {
		extractAttestedSBOM = originalExtract
		generateImageSBOM = originalGenerate
	})

	expected := &ResolvedSBOM{
		Source:   SourceGenerated,
		Format:   "syft-json",
		Packages: []NormalizedPackage{{Name: "openssl", Version: "3.0.0"}},
	}

	extractAttestedSBOM = func(context.Context, string) ([]byte, string, error) {
		return nil, "", attestation.ErrNoSBOMAttestation
	}
	generateImageSBOM = func(context.Context, string) (*ResolvedSBOM, error) {
		return expected, nil
	}

	resolved, err := ExtractSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if err != nil {
		t.Fatalf("ExtractSBOM returned error: %v", err)
	}

	if resolved != expected {
		t.Fatal("expected generated SBOM result to be returned")
	}
}

func TestExtractSBOM_FallsBackWhenAttestedPayloadCannotBeDecoded(t *testing.T) {
	originalExtract := extractAttestedSBOM
	originalGenerate := generateImageSBOM
	t.Cleanup(func() {
		extractAttestedSBOM = originalExtract
		generateImageSBOM = originalGenerate
	})

	expected := &ResolvedSBOM{
		Source:   SourceGenerated,
		Format:   "syft-json",
		Packages: []NormalizedPackage{{Name: "busybox", Version: "1.36.1"}},
	}

	extractAttestedSBOM = func(context.Context, string) ([]byte, string, error) {
		return []byte(`{"predicateType":"not-an-sbom"}`), "https://example.com/not-sbom", nil
	}
	generateImageSBOM = func(context.Context, string) (*ResolvedSBOM, error) {
		return expected, nil
	}

	resolved, err := ExtractSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if err != nil {
		t.Fatalf("ExtractSBOM returned error: %v", err)
	}

	if resolved != expected {
		t.Fatal("expected generated SBOM result after decode failure")
	}
}

func TestResolveAttestedSBOM_ReturnsDecodeErrorForInvalidPayload(t *testing.T) {
	originalExtract := extractAttestedSBOM
	t.Cleanup(func() {
		extractAttestedSBOM = originalExtract
	})

	extractAttestedSBOM = func(context.Context, string) ([]byte, string, error) {
		return []byte(`{"hello":"world"}`), "https://example.com/not-sbom", nil
	}

	_, err := resolveAttestedSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if err == nil {
		t.Fatal("expected decode error")
	}
	if errors.Is(err, attestation.ErrNoSBOMAttestation) {
		t.Fatal("expected decode failure, not missing-attestation signal")
	}
}
