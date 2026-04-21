package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestExtractSBOM_FallsBackToNotationWhenCosignHasNoSignedSBOM(t *testing.T) {
	originalCosign := extractSBOMWithCosign
	originalNotation := extractSBOMWithNotation
	t.Cleanup(func() {
		extractSBOMWithCosign = originalCosign
		extractSBOMWithNotation = originalNotation
	})

	extractSBOMWithCosign = func(context.Context, string) ([]byte, string, error) {
		return nil, "", ErrNoSBOMAttestation
	}
	extractSBOMWithNotation = func(context.Context, string) ([]byte, string, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`), "application/vnd.cyclonedx+json", nil
	}

	payload, predicateType, err := ExtractSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if err != nil {
		t.Fatalf("ExtractSBOM returned error: %v", err)
	}
	if predicateType != "application/vnd.cyclonedx+json" {
		t.Fatalf("unexpected predicate/media type: got %q", predicateType)
	}
	if len(payload) == 0 {
		t.Fatal("expected notation payload")
	}
}

func TestExtractSBOM_ReturnsMissingWhenNeitherVerifierFindsSBOM(t *testing.T) {
	originalCosign := extractSBOMWithCosign
	originalNotation := extractSBOMWithNotation
	t.Cleanup(func() {
		extractSBOMWithCosign = originalCosign
		extractSBOMWithNotation = originalNotation
	})

	extractSBOMWithCosign = func(context.Context, string) ([]byte, string, error) {
		return nil, "", ErrNoSBOMAttestation
	}
	extractSBOMWithNotation = func(context.Context, string) ([]byte, string, error) {
		return nil, "", ErrNoSBOMAttestation
	}

	_, _, err := ExtractSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if !errors.Is(err, ErrNoSBOMAttestation) {
		t.Fatalf("expected ErrNoSBOMAttestation, got %v", err)
	}
}

func TestExtractSBOM_PreservesPrimaryVerifierErrorWhenNotationAlsoHasNoSBOM(t *testing.T) {
	originalCosign := extractSBOMWithCosign
	originalNotation := extractSBOMWithNotation
	t.Cleanup(func() {
		extractSBOMWithCosign = originalCosign
		extractSBOMWithNotation = originalNotation
	})

	expectedErr := errors.New("cosign unavailable")
	extractSBOMWithCosign = func(context.Context, string) ([]byte, string, error) {
		return nil, "", expectedErr
	}
	extractSBOMWithNotation = func(context.Context, string) ([]byte, string, error) {
		return nil, "", ErrNoSBOMAttestation
	}

	_, _, err := ExtractSBOM(context.Background(), "example.com/acme/app:1.0.0")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
}

func TestIsSBOMArtifactType(t *testing.T) {
	tests := map[string]bool{
		"application/spdx+json":                 true,
		"application/vnd.cyclonedx+json":        true,
		"application/example+json;sbom":         true,
		"example/sbom":                          true,
		"application/vnd.cncf.notary.signature": false,
		"":                                      false,
		"application/example":                   false,
	}

	for artifactType, want := range tests {
		if got := isSBOMArtifactType(artifactType); got != want {
			t.Fatalf("isSBOMArtifactType(%q) = %v, want %v", artifactType, got, want)
		}
	}
}

func TestSBOMPredicatePayload_PreservesStringDocument(t *testing.T) {
	payload, err := os.ReadFile("../sbom/testdata/spdx.json")
	if err != nil {
		t.Fatal(err)
	}

	var asString string
	if err := json.Unmarshal(payload, &asString); err == nil {
		t.Fatal("expected SPDX fixture to be a JSON object, not a JSON string")
	}

	got, err := sbomPredicatePayload(string(payload))
	if err != nil {
		t.Fatalf("sbomPredicatePayload returned error: %v", err)
	}

	if string(got) != string(payload) {
		t.Fatal("expected string predicate payload to be returned without JSON re-encoding")
	}
}
