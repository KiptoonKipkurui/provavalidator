package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
)

var ErrNoSBOMAttestation = errors.New("no signed sbom attestation found")

var extractSBOMWithCosign = extractSBOMWithCosignImpl
var extractSBOMWithNotation = extractSBOMWithNotationImpl

// Verifier is the minimum interface sbom resolution depends on.
type Verifier interface {
	// ExtractSBOM extracts SBOM bytes from a verified signed attestation for the given image reference.
	ExtractSBOM(ctx context.Context, imageRef string) (sbomBytes []byte, predicateType string, err error)
}

type CosignVerifier struct{}

var _ Verifier = (*CosignVerifier)(nil)

func (v *CosignVerifier) ExtractSBOM(ctx context.Context, imageRef string) (sbomBytes []byte, predicateType string, err error) {
	return ExtractSBOM(ctx, imageRef)
}

func ExtractSBOM(ctx context.Context, imageRef string) (sbomBytes []byte, predicateType string, err error) {
	if _, err := name.ParseReference(imageRef); err != nil {
		return nil, "", fmt.Errorf("parse image ref: %w", err)
	}

	sbomBytes, predicateType, err = extractSBOMWithCosign(ctx, imageRef)
	if err == nil {
		return sbomBytes, predicateType, nil
	}

	cosignErr := err
	sbomBytes, predicateType, err = extractSBOMWithNotation(ctx, imageRef)
	if err == nil {
		return sbomBytes, predicateType, nil
	}

	if errors.Is(cosignErr, ErrNoSBOMAttestation) && errors.Is(err, ErrNoSBOMAttestation) {
		return nil, "", ErrNoSBOMAttestation
	}
	if errors.Is(err, ErrNoSBOMAttestation) {
		return nil, "", cosignErr
	}

	return nil, "", err
}

func extractSBOMWithCosignImpl(ctx context.Context, imageRef string) (sbomBytes []byte, predicateType string, err error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, "", fmt.Errorf("parse image ref: %w", err)
	}

	statements, err := verifyWithCosignStatements(ctx, ref, nil)
	if err != nil {
		return nil, "", err
	}

	for _, verified := range statements {
		if verified.Statement == nil || verified.Statement.Predicate == nil {
			continue
		}

		if !isLikelySBOMPredicateType(verified.Statement.PredicateType) {
			continue
		}

		payload, err := sbomPredicatePayload(verified.Statement.Predicate)
		if err != nil {
			return nil, "", err
		}

		return payload, verified.Statement.PredicateType, nil
	}

	return nil, "", ErrNoSBOMAttestation
}

func isLikelySBOMPredicateType(predicateType string) bool {
	switch predicateType {
	case "https://spdx.dev/Document", "https://cyclonedx.org/bom":
		return true
	default:
		return false
	}
}

func sbomPredicatePayload(predicate interface{}) ([]byte, error) {
	switch v := predicate.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		payload, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal sbom predicate: %w", err)
		}
		return payload, nil
	}
}
